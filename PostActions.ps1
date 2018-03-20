[CmdLetBinding()]
Param($Actions,[Switch]$Force,
    [switch]$DebugMode)
$Global:logFile = "$env:WinDir\AppLog\PostOOBE.ps1.log"

Start-Transcript -Path "$env:WinDir\AppLog\PostOOBE.Transcript.log"

function Get-OSBuild {
    cmd.exe /c ver 2>$null | ForEach-Object {
        $v = ([regex]'(\d+(\d+|\.))+').Matches($_).Value
        if ($v) {
            [Version]::Parse($v).Build
        }
    }
}

function logMsg {
    [CmdLetBinding()]
    Param(
        [Parameter(
            ValueFromPipeline=$True
        )]$Message,$logFile=$Global:logFile
    )
    "$(Get-Date): $Message" | Out-File -FilePath $logFile -Append
}

Function Test-MissingDrivers {
    [CmdLetBinding()]
    Param()
    $DriversHealthy = $True
    $i = 0
    $devices = Get-WmiObject Win32_PNPEntity | Where-Object{$_.ConfigManagerErrorCode -ne 0} | Select-Object Name, DeviceID
    $devices | ForEach-Object {$i++} 

    if ($i -ge 1) {
        #1 or more drivers missing
        logMsg "$i unknown or faulty driver(s)" 
        
        foreach ($device in $devices) {
           logMsg ('Missing or faulty driver: ' +$device.Name + '. Device ID: ' + $device.DeviceID)
        }
        $DriversHealthy = $False
    }
    else {
        logMsg "Drivers: OK"
    }
    return $DriversHealthy
}

function Enable-Login {
    [CmdLetBinding()]
    Param()

    $WinLogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\'
    #Obtain the value of the Userinit backup reg value
    $Userinit = (Get-ItemProperty -path $WinLogonPath -Name Userinit_Orig -EA SilentlyContinue).Userinit_Orig
    If (-Not $Userinit) {
        Write-Error "Unable to find backup reg key Userinit_Orig"
    } else {
        #Set the Userinit reg value to the value previously obtained
        Set-ItemProperty -Path $WinLogonPath -Name Userinit -Value $Userinit
        #Remove the backed up userinit value
        Remove-ItemProperty -Path $WinLogonPath -Name Userinit_Orig
    }
}

function Disable-Login {
    [CmdLetBinding()]
    Param()

    #Block login by changing the userinit regkey to a logout command
    #First we copy the current value of userinit to userinit_orig
    $WinLogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\'
    $Userinit = (Get-ItemProperty -path $WinLogonPath -Name Userinit).Userinit
    If (Get-ItemProperty -Path $WinLogonPath -Name Userinit_Orig -EA SilentlyContinue) {
        Write-Error "Userinit_Orig already exists. Likely login is already disabled"
    } else {
        New-ItemProperty -Path $WinLogonPath -Name Userinit_Orig -PropertyType String -Value $Userinit
        #Now we update the value of userinit to logoff the user
        Set-ItemProperty -Path $WinLogonPath -Name Userinit -Value 'shutdown.exe /l'
    }
}

If (-Not $Actions) {
    #Note - When building actionlist, remember actions are completed in reverse order
    #Build action list
    logMsg "Building action list..."
    logMsg "Adding AppXPackages"
    [array]$arrActions += 'AppXPackages'
    $ARPEntry = get-childitem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ | Where-Object {
        (Get-ItemProperty -Path $_.PSPath -Name DisplayName -EA SilentlyContinue).DisplayName -match 'Dell Command | Monitor'
    }
    If ($ARPEntry){
        logMsg "Adding DellWMI"
        [array]$arrActions += 'DellWMI'
    }
    $RSATSource = "$($env:SystemRoot)\Resources\USC\RSAT"
    if (Test-Path -Path $RSATSource){
        logMsg "Adding RSAT"
        [array]$arrActions += 'RSAT'
    }
    If (Test-Path -Path $env:SystemDrive\_vNextDrivers) {
        logMsg "Adding action DriverCleanup"
        [array]$arrActions += 'DriverCleanup'

        If ((Get-OSBuild) -eq '16299') {
            logMsg "Adding action ReapplyDrivers due to a bug in 1709"
            logMsg "Checking if drivers are healthy"
            If (Test-MissingDrivers) {
                logMsg "All drivers accounted for. No need to reapply"
            } else {
                logMsg "Some drivers are missing, attempt to reapply"
                [array]$arrActions += 'ReapplyDrivers'
            }
        }
    }
    If (Test-Path -Path $env:SystemDrive\Users\Default\AppData\Local\Microsoft\Windows\WSUS\SetupConfig.ini) {
        logMsg "Adding action cleanup PostOOBE Scripts"
        [array]$arrActions += 'PostOOBECleanup'
    }
} else {
    # In this instance we have probably been launched from a scheduled Task. Clear it off
    if (Get-ScheduledTask -TaskName PostOOBE -ErrorAction SilentlyContinue) {
        logMsg "Removing Scheduled task"
        Unregister-ScheduledTask -TaskName PostOOBE -Confirm:$False
    }
    [array]$arrActions = $Actions -Split ','
}
function Invoke-Schedule {
    Param($arrActions,[Switch]$Force,$RebootCommand)
    If ($arrActions) {
        If (-Not (Get-ScheduledTask -TaskName PostOOBE)) {
            logMsg "Creating Scheduled task"
                $TaskXML = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\PostOOBE</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
  </Settings>
  <Triggers>
    <BootTrigger>
    </BootTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>"C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe"</Command>
      <Arguments>-File $PSCommandPath -Actions $($arrActions -Join ',')</Arguments>
    </Exec>
  </Actions>
</Task>
"@
            $TaskDefFile = New-Item -ItemType File -Path $env:Temp -Name (Get-Random) -Value $TaskXML 
            #schtasks.exe /Create /F /RU "SYSTEM" /SC ONSTART /TN PostOOBE /TR "'C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe' -File $PSCommandPath -Actions $($arrActions -Join ',')" /RL Highest
            schtasks.exe /Create /F /XML $TaskDefFile /TN PostOOBE
            If ($?) {
                logMsg "Succesfully created Scheduled task"
                Remove-Item $TaskDefFile
            } else {
                logMsg "Failed to create task. Leaving task artifact $TaskDefFile"
            }
        }
    }
    If (((Get-Process -Name explorer -ErrorAction SilentlyContinue).Count -eq 0) -or $Force) {
        If ($RebootCommand -eq $True) {
            logMsg "Restarting using built in command"
            Restart-Computer -Force:$Force
        } Elseif ($RebootCommand) {
            logMsg "Restating with: $RebootCommand"
            Invoke-Expression $RebootCommand
        }
    } else {
        logMsg "Detected a logged on user. wait for user to reboot"
    }
}

Do {
    # Working on last action first.
    $WorkingAction = $arrActions[$arrActions.Count -1]
    # Reinstantiate the list without the last action.
    $arrActions = for ($i=0; $i -lt $arrActions.Count -1; $i++) {$arrActions[$i]}

    Switch($WorkingAction){
        'AppXPackages'{
            logMsg "Working on AppXPackages"
            $IsShared = (Get-ItemProperty -Path HKLM:\Software\USC -Name IsShared -EA SilentlyContinue).IsShared
            If ($IsShared -eq 1) {
                logMsg "Detected Shared config. Setting up applist"
                $AppsList = "Microsoft.3DBuilder","Microsoft.BingFinance","Microsoft.BingNews","Microsoft.BingSports","Microsoft.BingWeather","Microsoft.Getstarted","Microsoft.Messaging","Microsoft.MicrosoftOfficeHub","Microsoft.MicrosoftSolitaireCollection","Microsoft.Office.OneNote","Microsoft.Office.Sway","Microsoft.OneConnect","Microsoft.People","Microsoft.SkypeApp","Microsoft.WindowsAlarms","microsoft.windowscommunicationsapps","Microsoft.WindowsFeedbackHub","Microsoft.WindowsMaps","Microsoft.WindowsPhone","Microsoft.XboxApp","Microsoft.XboxIdentityProvider","Microsoft.ZuneMusic","Microsoft.ZuneVideo"
            } else {
                logMsg "Detected NonShared config. Setting up applist"
                $AppsList = "Microsoft.SkypeApp","Microsoft.MicrosoftOfficeHub","Microsoft.ConnectivityStore","Microsoft.OneConnect"
            }
        
            ForEach ($App in $AppsList) {
                $Packages = Get-AppxPackage | Where-Object {$_.Name -eq $App}
                if ($Packages -ne $null) {
                    logMsg "Removing Appx Package: $App"
                    foreach ($Package in $Packages) {
                        Remove-AppxPackage -package $Package.PackageFullName
                    }
                } else {
                    logMsg "Unable to find package: $App"
                }
        
                $ProvisionedPackage = Get-AppxProvisionedPackage -online | Where-Object {$_.displayName -eq $App}
                if ($ProvisionedPackage -ne $null) {
                    logMsg "Removing Appx Provisioned Package: $App"
                    remove-AppxProvisionedPackage -online -packagename $ProvisionedPackage.PackageName
                } else {
                    logMsg "Unable to find provisioned package: $App"
                }
        
            }
        }
        'RSAT'{
            logMsg "Working on RSAT"
            # Install RSAT
            #Do we need to re-install RSAT?
            $RSATSource = "$($env:SystemRoot)\Resources\USC\RSAT"
            if (Test-Path -Path $RSATSource){
                $MSU = Get-ChildItem -Path $RSATSource -Filter *.msu | Select-Object -First 1
                $Params = @{
                    FilePath = "$env:SystemRoot\system32\wusa.exe"
                    ArgumentList = "$($MSU.FullName) /quiet /norestart /log:""$($env:SystemRoot)\AppLog\RSAT Install (64-bit).log"""
                    Wait = $True
                    PassThru = $True
                }
                logMsg ("Running Command: {0} {1}" -f $Params.FilePath,$Params.ArgumentList)
                $ProcObj = Start-Process @Params
                if ($ProcObj.ExitCode -eq 3010) {
                    $RebootCommand = $True
                }
            }
        }
        'DellWMI' {
            logMsg "Working on DellWMI"
            # Repair Dell WMI
            Try {
                Get-WMIObject -NameSpace root\dcim\sysman -Class DCIM_BiosService -ErrorAction Stop | Out-Null
                # If we have gotten here without an exception. The service is compliant.
                logMsg "Succesfully queried the DCIM\Sysman DCIM_BiosService. No repair needed"
            } Catch {
                # Assuming we have hit an exception, this means that we cannot attach to the service and the app needs to be repaired
                # As this is a PostOOBE script, we will attempt the repair now.
                logMsg "Failed to query the DCIM\Sysman DCIM_BiosService. We will attempt repair"
                logMsg "Since this repair has shown to force a reboot, we will schedule this script to resume"
                #Check if Hyper-V will need a repair.
                $HyperV = Get-WindowsOptionalFeature -online -featurename Microsoft-Hyper-V-Hypervisor
                #Fix Hyper-V Install
                If ($HyperV.State -eq "Enabled") {
                    logMsg "Detected a Hyper-V repair will be needed after DellWMI, adding to actions"
                    $arrActions += 'Hyper-V'
                }
                # When using /f on an MSI, MSI Parameters (like REBOOT=REALLYSUPPRESS) are ignored. Therefore, before we repair
                # we will run a script which will update the cached MSI first and set it to ReallySuppress.
                $UpdateMSIScript = "$(Split-Path -Path $PSCommandPath -Parent)\Update-MSIRebootOption.ps1"
                logMsg "Checking and updating locally cached MSI REBOOT Property"
                Start-Process -FilePath powershell.exe -ArgumentList "-File ""$UpdateMSIScript"" -MSICode ""$($ARPEntry.PSChildName)"" -LogFile  $Global:logFile" -Wait
                logMsg "Starting Dell Command | Monitor MSI repair"
                Start-Process -FilePath msiexec.exe -ArgumentList "/fam ""$($ARPEntry.PSChildName)"" /l* ""$($env:Systemroot)\AppLog\DellWMIRepair.log"" /qn" -Wait
            }
        }
        'Hyper-V'{
            logMsg "Working on Hyper-V"
            # Recompile Hyper-V MOF
            logMsg "Repairing Hyper-V after Dell Command | Monitor repair"
            $Path = "$env:SystemRoot\System32\WindowsVirtualization.V2.mof"
            $MofComp = Get-Item 'C:\Windows\System32\wbem\mofcomp.exe'
            logMsg "Running: $MofComp $Path"
            Invoke-expression "$MofComp $Path"
            If ($?) {
                logMsg "Succesfully compiled mof $Path"
            } Else {
                logMsg "Failed to compile mof"
            }
        }
        'ReapplyDrivers' {
            logMsg "Working on Reapply Drivers to work around issue mentioned in KB4090913"
            logMsg "Reapplying drivers can take a while and a reboot is required before and after. Temporarily block the user from logging in"
            Disable-Login
	    $arrActions += 'ApplyDriversAfterReboot'
            logMsg "Issue a reboot and resume with new action, ApplyDriversAfterReboot"
            $RebootCommand = $True # Reboot before installing drivers
        }
        'ApplyDriversAfterReboot' {
            logMsg "System started, apply drivers now"
            Get-ChildItem $env:SystemDrive\_vNextDrivers -Recurse -Filter "*.inf" | 
                ForEach-Object { 
                    logMsg "Executing PNPUtil on $($_.FullName)"
                    PNPUtil.exe /add-driver $_.FullName /install 
                    if ($?) {
                        logMsg "Succesfully added $($_.Fullname)"
                    } else {
                        logMsg "Succesfully added $($_.Fullname)"
                    }
                }
	    If ($DebugMode) {
		while (-Not (Get-ItemProperty -Path HKLM:\Software\USC -Name DebugPostOOBEContinue -EA Si).DebugPostOOBEContinue -eq 1) {
	            logMsg "Waiting for debug continue flag at hklm\software\usc DebugPostOOBEContinue"
	 	    Start-Sleep -Seconds 300
	    	}
	    }
            logMsg "Re-enable login and reboot"
            Enable-Login
            $RebootCommand = $True # Reboot after installing drivers
        }
        'DriverCleanup'{
            logMsg "Working on Driver cleanup"
            Remove-Item -Path $env:SystemDrive\_vNextDrivers -Recurse -Force
            if ($?) {
                logMsg "Sucessfully removed vNext drivers"
            } else {
                logMsg "Failed to cleanup vNext drivers"
            }
        }
        'PostOOBECleanup' {
            logMsg "Working on Post OOBE Script cleanup"
            Remove-Item -Path $env:SystemDrive\Users\Default\AppData\Local\Microsoft\Windows\WSUS -Recurse -Force -ErrorAction SilentlyContinue
            If ($?) {
                logMsg "Succesfully removed PostOOBE config files"
            } else {
                logMsg "Failed to remove PostOOBE config files"
            }
        }
    }
} Until ($arrActions -eq $null -or $RebootCommand)

If ($RebootCommand){
    logMsg "A Reboot is required"
    If ($arrActions) {
        logMsg "Actions are still in the list"
        $arrActions | ForEach-Object { logMsg "Still to perform: $_" }
        Invoke-Schedule -arrActions $arrActions -RebootCommand $RebootCommand -Force:$Force
    } else {
        logMsg "No more actions."
        if (Get-ScheduledTask -TaskName PostOOBE -ErrorAction SilentlyContinue) {
            logMsg "Removing Scheduled task"
            Unregister-ScheduledTask -TaskName PostOOBE -Confirm:$False
        }
    }
} else {
    # If there are no reboots, then it also means there are no actions.
    logMsg "No reboots and no actions left"
    if (Get-ScheduledTask -TaskName PostOOBE -ErrorAction SilentlyContinue) {
        logMsg "Removing scheduled task"
        Unregister-ScheduledTask -TaskName PostOOBE -Confirm:$False
    }
}

Stop-Transcript
