rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90415d8f9e93c8d1a466edf4fef7ccff0e7cd3f1505f188b9a69c42826bca1db"

  strings:
    $s1 = "Select CommandLine from Win32_Process where Name='{0}'" fullword wide
    $s2 = "SELECT Name, VideoProcessor FROM Win32_VideoController" fullword wide
    $s3 = "/C choice /C Y /N /D Y /T 3 & Del \"" fullword wide
    $s4 = "\"' & exit" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}