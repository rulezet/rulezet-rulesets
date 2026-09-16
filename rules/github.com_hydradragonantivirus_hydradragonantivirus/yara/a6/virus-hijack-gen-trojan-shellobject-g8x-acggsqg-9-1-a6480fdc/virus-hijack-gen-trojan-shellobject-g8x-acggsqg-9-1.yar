rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCggSqg_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCggSqg_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58e1c8fa408766a46c072e011807c90b72aab967f6625a02c38eacf8b413f4f9"

  strings:
    $s1 = "Mastitis" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}