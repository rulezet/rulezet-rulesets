rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_349_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_349_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc1905ed3bc70a9afda2c9f279a462976307fb070103a0f4207fdb5b9321cea3"

  strings:
    $s1 = "66by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}