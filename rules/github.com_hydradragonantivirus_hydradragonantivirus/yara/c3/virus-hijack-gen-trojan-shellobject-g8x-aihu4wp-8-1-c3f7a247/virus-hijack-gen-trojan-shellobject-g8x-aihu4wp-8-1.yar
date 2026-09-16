rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d73d6d64734797e0bd7b001b5118c4131843f89597a37b23b82895d8598ff5ba"

  strings:
    $s1 = "Paragon" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}