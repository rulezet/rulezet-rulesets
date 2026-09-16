rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_177_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_177_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b86c73d289bf0cf57c973305ef20c7b9b1caa47d923fa8bc1652d488b7ff274"

  strings:
    $s1 = "qQ2013 software. For your convenience, we" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}