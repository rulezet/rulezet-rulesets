rule Trojan_Danger_Gen_Trojan_Heur_cuY_HPIO3zfb_6_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Trojan.Heur.cuY@HPIO3zfb_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6410f1f728f6d71b4c816eded50baab0e308f1bbf43be1063d1da0d5ebe1c7b"

  strings:
    $s1 = "eautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}