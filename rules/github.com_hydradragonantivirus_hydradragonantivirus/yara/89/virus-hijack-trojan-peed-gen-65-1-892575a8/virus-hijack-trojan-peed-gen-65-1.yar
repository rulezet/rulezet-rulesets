rule Virus_Hijack_Trojan_Peed_Gen_65_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_65_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9edf8d5a38648d989a62af64cee04873e5ad2128d495be3bdc16ef7ac9fd5030"

  strings:
    $s1 = "RIBE!p" fullword ascii
    $s2 = "<riSt." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}