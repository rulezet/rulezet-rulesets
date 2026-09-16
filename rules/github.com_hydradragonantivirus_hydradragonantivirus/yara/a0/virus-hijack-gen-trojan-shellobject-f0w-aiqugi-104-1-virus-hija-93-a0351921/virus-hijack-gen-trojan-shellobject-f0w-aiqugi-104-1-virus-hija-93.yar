import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_104_1_Virus_Hija_93 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_104_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_105_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_106_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1402d55ebe79764aa6b500d90065bfe6cac3be6e4b121d503aade48ba3beab58"
    hash2       = "b855bce10c0efd4998e88e95f6bfa4a2f6088c7c5b1befadcff2bb2045f159c7"
    hash3       = "7c9e89c6d6226a5bbb0a4027211b230c847f293a3162d91841125bf0ad032ad9"

  strings:
    $x1  = "<!DOCTYPE Sysmon [<!ELEMENT Sysmon (EventFiltering|ArchiveDirectory|CaptureClipboard|DriverName|PipeMonitoringConfig|HashAlgorit" wide
    $x2  = "%s[-] ShellExecute Param for CmdFirewall.exe = %s" fullword wide
    $s3  = "[SamsungDeX Connection] sendKeyboardEvent - %d, ScanCode = %ld(%02X,%02X,%02X,%02X), Result = %d" fullword wide
    $s4  = "[SamsungDeX Connection] sendKeyboardEvent - %d, ScanCode = %ld(%02X,%02X,%02X,%02X)" fullword wide
    $s5  = "[%s] Mutex lock aquired for tray agent click" fullword wide
    $s6  = "[%s] > pSubLogic == NULL --> PSS_DISCONNECTED" fullword wide
    $s7  = "[SamsungDeX Connection][ALARM] Anomaly detected - Another KMS connection in progress. Failed to achieve lock" fullword wide
    $s8  = "[%s] Update check process has been started." fullword wide
    $s9  = "[%s] ReadDirectoryChangesW() returns FALSE. (GetLastError() returns 0x%08X.)" fullword wide
    $s10 = "[%s][IE PLUGIN] Didn't Copy Data! - Device was not connected." fullword wide
    $s11 = "[SamsungDeX Connection - MainControlEvent::ChangeKmsStateSuccess] PSS has been stopped by main control" fullword wide
    $s12 = "[%s]  PUBLIC FireWallIsOn = %s, PRIVATE FireWallIsOn = %s DOMAIN FireWallIsOn = %s" fullword wide
    $s13 = "\\pard\\fi-357\\li357\\sb120\\sa120\\tx360\\b\\fs20 3.\\tab SENSITIVE INFORMATION. \\b0  Please be aware that, similar to other " ascii
    $s14 = "[SamsungDeX Connection] Driver install failed" fullword wide
    $s15 = "[SamsungDeX Connection] Parameter error (%d)" fullword wide
    $s16 = "[%s] BeginDeferWindowPos() returns NULL. (GetLastError() returns 0x%08X.)" fullword wide
    $s17 = "[%s] DeferWindowPos() returns NULL. (GetLastError() returns 0x%08X.)" fullword wide
    $s18 = "[%s] EndDeferWindowPos() returns FALSE. (GetLastError() returns 0x%08X.)" fullword wide
    $s19 = "[%s] CloseHandle() returns FALSE. (GetLastError() returns 0x%08X.)" fullword wide
    $s20 = "[%s](-) CreateFile() returns NULL. (GetLastError() returns 0x%08X.)" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "08b67a9663d3a8c9505f3b2561bbdd1c" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}