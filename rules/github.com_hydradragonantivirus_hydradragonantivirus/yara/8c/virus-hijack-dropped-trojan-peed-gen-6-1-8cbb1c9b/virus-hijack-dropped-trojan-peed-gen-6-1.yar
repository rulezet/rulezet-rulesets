rule Virus_Hijack_Dropped_Trojan_Peed_Gen_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Trojan.Peed.Gen_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "162b658fc8cdbc946f48057874da7aaa982d0c0dc64815a17d263698cc185558"

  strings:
    $s1 = "orvietan" fullword wide
    $s2 = "Stibiconite" fullword wide
    $s3 = "Sacking" fullword wide
    $s4 = "?Cell%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}