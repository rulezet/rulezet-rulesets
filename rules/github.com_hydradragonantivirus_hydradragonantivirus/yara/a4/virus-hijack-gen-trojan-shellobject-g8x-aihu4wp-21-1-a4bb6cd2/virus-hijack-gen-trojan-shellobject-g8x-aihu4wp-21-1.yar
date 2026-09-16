rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_21_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35bc6e07f576a9a02ea28a7b4dad8fd17d0d03508308ef7781579a333e4a463b"

  strings:
    $s1 = "Yourselves" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}