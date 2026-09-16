rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_76_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_76_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a4df487e74f17dbe2df7d5d7d839b86b39720bd50a1bd8544232843da603be2"

  strings:
    $s1 = "gHor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}