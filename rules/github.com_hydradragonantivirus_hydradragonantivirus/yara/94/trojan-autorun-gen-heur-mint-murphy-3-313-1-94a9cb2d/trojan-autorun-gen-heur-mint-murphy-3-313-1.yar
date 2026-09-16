rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_313_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_313_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f789e9708fa9b09f4831d3e9ab9da1dd9318a761fce74d74ad4b79183e67b39d"

  strings:
    $s1 = "X?by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}