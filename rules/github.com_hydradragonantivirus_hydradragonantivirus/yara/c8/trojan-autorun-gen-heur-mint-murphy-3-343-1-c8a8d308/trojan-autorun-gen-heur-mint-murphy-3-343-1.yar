rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_343_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_343_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f70a3985e73af019646baef26226559f79656a96fb4946658adf89d288c3fd3f"

  strings:
    $s1 = "_4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}