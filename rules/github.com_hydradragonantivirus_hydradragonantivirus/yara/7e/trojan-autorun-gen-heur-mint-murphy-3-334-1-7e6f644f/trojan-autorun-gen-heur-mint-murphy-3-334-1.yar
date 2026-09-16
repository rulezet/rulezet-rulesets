rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_334_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_334_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a9ac03a4258512e97c738414a47e2c26feb90786bbabf6ad3f97da09c9f270e"

  strings:
    $s1 = "3or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}