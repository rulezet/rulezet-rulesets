rule Virus_Hijack_Trojan_Peed_Gen_25_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "241bd45b1651a60d4ce47835f9c62aa08f969743e8d275fea3cb0d8e2968332f"

  strings:
    $s1 = "]dEBT`d%" fullword ascii
    $s2 = "T_ BOwL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}