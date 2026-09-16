rule Virus_Hijack_Gen_Trojan_ShellObject_gyY_aWevApi_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyY@aWevApi_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee24d9af1ef27e63bfe2192b645d26e8e1b94c349897a08ada30dd559e691b16"

  strings:
    $s1 = "Unproduced" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}