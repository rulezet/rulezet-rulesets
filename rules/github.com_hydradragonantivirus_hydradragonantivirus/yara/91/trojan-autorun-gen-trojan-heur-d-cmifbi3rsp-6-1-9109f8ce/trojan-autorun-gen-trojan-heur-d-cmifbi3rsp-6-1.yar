rule Trojan_Autorun_Gen_Trojan_Heur_D_cmIfbi3RsP_6_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "498ffbb3d3fde18948db02388ebfc3884e372108eb2c6672ef7b5828c88dff11"

  strings:
    $s1 = "hby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}