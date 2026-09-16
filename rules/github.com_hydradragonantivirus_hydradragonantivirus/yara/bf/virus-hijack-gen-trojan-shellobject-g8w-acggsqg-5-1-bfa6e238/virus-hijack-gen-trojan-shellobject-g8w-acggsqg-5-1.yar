rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aCggSqg_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aCggSqg_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d79670caa70d31d4f17cdfe05874114f91cd0089bef1aee1a9c9fddcc8e0f94f"

  strings:
    $s1 = "J gAUR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}