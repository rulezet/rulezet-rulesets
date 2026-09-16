rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_337_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_337_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d0a506097efc73d68e926c312145771fd8448e8b21502f55dfdaeb6443b133f"

  strings:
    $s1 = "qor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}