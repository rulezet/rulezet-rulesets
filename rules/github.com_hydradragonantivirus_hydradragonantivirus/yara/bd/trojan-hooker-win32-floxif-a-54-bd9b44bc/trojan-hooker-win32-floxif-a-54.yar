rule Trojan_Hooker_Win32_Floxif_A_54 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_54.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "936cbb4029aed04b504442340b2cca832cd53d08ad7f463bd9effdc7c70bc9b1"

  strings:
    $x1  = "add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SppExtComObj.Exe\" /f /v \"Debugger\"" wide
    $x2  = "start \"\" /wait msiexec.exe /package {%ProduGuid%} /uninstall {%ProduUpdaGuid%} /qn /log %TEMP%\\my_log_msi.log" fullword ascii
    $x3  = "delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SppExtComObj.Exe\" /f /v \"KMS_Emu" wide
    $x4  = "add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SppExtComObj.Exe\" /f /v \"KMS_Emulat" wide
    $x5  = "add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SppExtComObj.Exe\" /f /v \"Debugger\"" wide
    $x6  = "delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SppExtComObj.Exe\" /f /v \"Debugge" wide
    $x7  = "<nul set /p \"=<?xml version=\"1.0\" encoding=\"utf-8\"?><genuineAuthorization xmlns=\"http://www.microsoft.com/DRM/SL/GenuineAu" ascii
    $x8  = "-U:T -P:E -ShowWindowMode:Hide -Wait powershell.exe -ExecutionPolicy bypass -File \"" fullword wide
    $x9  = "%psc% \"!tls! irm https://licensing.mp.microsoft.com/v7.0/licenses/content -Method POST\" | find /i \"traceId\" %nul1% || set re" ascii
    $x10 = "%psc% \"!tls! irm https://licensing.mp.microsoft.com/v7.0/licenses/content -Method POST\" | find /i \"traceId\" %nul1% || set re" ascii
    $x11 = "delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SppExtComObj.Exe\" /f" fullword wide
    $x12 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><a" ascii
    $x13 = "for /f \"tokens=* delims=\" %%i in ('%psc% [conv%f%ert]::ToBas%f%e64String([Text.En%f%coding]::Uni%f%code.GetBytes(\"\"\"!string" ascii
    $x14 = "del /q %TEMP%\\my_log_msi.log" fullword ascii
    $x15 = "if %_wmic% EQU 1 for /f \"tokens=2 delims==\" %%a in ('\"wmic Path Win32_OperatingSystem Get OperatingSystemSKU /format:LIST\" %" ascii
    $x16 = "set d1=%ref% [void]$TypeBuilder.DefinePInvokeMethod('SLGetWindowsInformationDWORD', 'slc.dll', 'Public, Static', 1, [int], @([St" ascii
    $x17 = "echo \"%error_code%\" | findstr /i \"0x800410 0x800440\" %nul1% && set wmifailed=1& ::  https://learn.microsoft.com/en-us/window" ascii
    $x18 = "if %_wmic% EQU 1 for /f \"tokens=2 delims==\" %%a in ('\"wmic Path Win32_OperatingSystem Get OperatingSystemSKU /format:LIST\" %" ascii
    $x19 = "set d1=%ref% [void]$TypeBuilder.DefinePInvokeMethod('SLGetWindowsInformationDWORD', 'slc.dll', 'Public, Static', 1, [int], @([St" ascii
    $x20 = "echo \"%error_code%\" | findstr /i \"0x800410 0x800440\" %nul1% && set wmifailed=1& ::  https://learn.microsoft.com/en-us/window" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}