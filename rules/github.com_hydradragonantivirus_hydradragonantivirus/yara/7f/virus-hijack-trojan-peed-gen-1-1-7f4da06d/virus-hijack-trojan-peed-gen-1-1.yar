rule Virus_Hijack_Trojan_Peed_Gen_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "644a4575d51e43fdf35ba6f6bfbfc453e9f2ead865d9635306c6584d4054298c"

  strings:
    $s1 = "loX]!GiRL" fullword ascii
    $s2 = "iG!KAka" fullword ascii
    $s3 = "oDuM(k" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}