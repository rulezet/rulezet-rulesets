rule Trojan_Hooker_Win32_Floxif_A_56 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_56.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b282d95c61fbc0cb3354df725e90d2c21bedc8ee7c4c7b70b87fb04830b40fdb"

  strings:
    $x1  = "ProcessCommandLine - Unable to construct 'base' logdir, or it does not exist [%s] " fullword wide
    $x2  = "ProcessCommandLine - Unable to create logdir [%s], reverting to 'base' [%s]" fullword wide
    $x3  = "SetupInfo -  ##%s DllGetVersion Load address failure [%s]" fullword wide
    $s4  = "SetupInfo::QuerySupportedOS: MsiViewExecute for database %s fails: error code [%d]" fullword wide
    $s5  = "Only one instance of Setup can run at a time.N%s Setup has failed.  If the problem persists, please contact Product Support.7Cre" wide
    $s6  = "Prerequisite ComponentseThis installation is not supported on this operating system version." fullword wide
    $s7  = "The setup application will exit.;Make sure both source file and destination directory exist.<Encryption Usage:Setup.exe /enc <sr" wide
    $s8  = "Setup - progress dialog initialization Thread and timer started" fullword wide
    $s9  = "Resource DLL Load Failed! ProInst - LangId = %04x, %s" fullword wide
    $s10 = "Setup - GetOsType OSType ::GetVersionEx faild!" fullword wide
    $s11 = "Setup - CopyInstallSuiteFiles copy file from[%s] to[%s] fails!" fullword wide
    $s12 = "Setup - DeleteInstallerFiles Copy from [%s] to [%s] fails!" fullword wide
    $s13 = "Setup - GetMSIFileSize fails!" fullword wide
    $s14 = "Setup - GetMSICurrent directory[%s]!" fullword wide
    $s15 = "Setup - GetMSICurrentFileSize fails!" fullword wide
    $s16 = "CA_win - StopSCMService - Error ControlService sent to service [%s] failed with error [%x]" fullword wide
    $s17 = "Setup - Init tick and file size  error code[%d]" fullword wide
    $s18 = "Setup - ParseXMLData failed File name [%s]" fullword wide
    $s19 = "Setup - Installer version[%d]" fullword wide
    $s20 = "Setup - .NET framework pre-installed" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}