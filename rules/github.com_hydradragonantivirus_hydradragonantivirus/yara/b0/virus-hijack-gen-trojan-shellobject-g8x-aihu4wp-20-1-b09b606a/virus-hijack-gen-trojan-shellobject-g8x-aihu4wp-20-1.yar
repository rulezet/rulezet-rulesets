rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_20_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afdd24e41ed1ea9e0043fa8bf356c5bca1c89be71e4dd7421382b65c545ae7c9"

  strings:
    $s1 = "Torsion" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}