rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_aaT6Wyj_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@aaT6Wyj_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46fddf11e587dbbed4a17cf26d657c5b1a9ab301b8a1194704ba3fed2de26e93"

  strings:
    $s1 = "<description>Takenforex</description>" fullword ascii
    $s2 = "Takenforex Version 1.12" fullword wide
    $s3 = "doesn't exist. " fullword wide
    $s4 = "About Takenforex" fullword wide
    $s5 = "Takenforex Internal" fullword wide
    $s6 = "ity Waning" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}