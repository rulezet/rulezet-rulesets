rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_314_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_314_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e23b59e2c5a22815d759adc970021abbc5a82a43baabc1969bd0da6cb4796542"

  strings:
    $s1 = "<<MAni" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}