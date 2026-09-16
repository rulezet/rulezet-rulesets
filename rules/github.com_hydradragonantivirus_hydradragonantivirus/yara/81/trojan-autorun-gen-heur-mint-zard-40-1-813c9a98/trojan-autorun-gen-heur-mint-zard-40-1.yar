rule Trojan_Autorun_Gen_Heur_Mint_Zard_40_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Zard.40_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8d91db78fb6f5f5f82034d26fe8d24f6688de1e23a35dcd301fd758f62bab56"

  strings:
    $s1 = ":by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}