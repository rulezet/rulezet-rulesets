rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCggSqg_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCggSqg_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd7deb1829fb3f0fec75dd12cb03c4ae1084f831b32b13d8520ffbbc7df2a79e"

  strings:
    $s1 = "Mellowly" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}