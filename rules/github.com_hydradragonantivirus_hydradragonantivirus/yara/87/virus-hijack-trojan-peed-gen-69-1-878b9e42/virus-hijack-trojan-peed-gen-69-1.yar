rule Virus_Hijack_Trojan_Peed_Gen_69_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_69_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1abae823e0fc4b895617ab35ad44703cafb33c3855f8b57712fd36431610961"

  strings:
    $s1 = "OdsO>7(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}