rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1214fcadfa9bdab5d9ee94cc705504d03dd6ea2e60ef2f2ed798103163ada133"

  strings:
    $s1 = "bWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}