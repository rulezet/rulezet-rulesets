rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aKzulAn_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aKzulAn_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06e05ee365eba87a80647c9f3ef66a62bf0736073dfee94fe0d82a28cf0933ca"

  strings:
    $s1 = "Select CommandLine, ProcessID from Win32_Process" fullword wide
    $s2 = "SELECT Name, VideoProcessor FROM Win32_VideoController" fullword wide
    $s3 = "FoAm'k*B:" fullword ascii
    $s4 = "LUlL<X" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}