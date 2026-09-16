rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_42_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_42_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b847cdc384665d1438d249b92de748e8ba358033d44415b1a1ff88ed826b8f4"

  strings:
    $s1 = "other Person.00" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}