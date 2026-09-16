rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28c01b8f51a05c2ba56a72ab01540af382a1e3135e16645dde837db6e9835560"

  strings:
    $s1 = "Monochromy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}