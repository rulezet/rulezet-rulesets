rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCggSqg_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCggSqg_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2103cbc87e5becd72537d26f39af5dc45fba3bf120c8fbecb31ccd20c4748f1"

  strings:
    $s1 = "Tattery" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}