rule _Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oUJio_12_1_Virus_Hija_394 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oUJio_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oUJio_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eebe64ee281bb927d94c41682164be53496f58a8bab12ee832ab254bd3a2aedf"
    hash2       = "59bec145960b3ed3d57eb6661ab4511c679ee84f9bacb80713e9ac9964d4d17e"

  strings:
    $s1 = "        <component name=\"Microsoft-Windows-BaseCrashDumpSettings\"" fullword ascii
    $s2 = "        <component name=\"Microsoft-Windows-themeservice\"" fullword ascii
    $s3 = "        <component name=\"Microsoft-Windows-OfflineFiles-Service\"" fullword ascii
    $s4 = "        <component name=\"Microsoft-Windows-Networking-Internet_Authentication_Service_DataStore\"" fullword ascii
    $s5 = "        <component name=\"Microsoft-Windows-scrnsave\"" fullword ascii
    $s6 = "        <component name=\"Microsoft-Windows-OfflineFiles-Core\"" fullword ascii
    $s7 = "        <component name=\"Microsoft-Windows-explorer\"" fullword ascii
    $s8 = "                [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CscService!Start]" fullword ascii
    $s9 = "                [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Csc!Start]" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}