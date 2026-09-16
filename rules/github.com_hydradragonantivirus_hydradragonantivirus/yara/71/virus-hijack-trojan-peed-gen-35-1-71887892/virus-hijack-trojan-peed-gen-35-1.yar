rule Virus_Hijack_Trojan_Peed_Gen_35_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_35_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be4db0bc25ef824f0cd432df35989cf14a857220766b5a203613f8e29ce49af8"

  strings:
    $s1 = "H{MONa" fullword ascii
    $s2 = "SkeR*C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}