rule Trojan_Danger_Gen_Trojan_Heur_cuY_HPIO3zfb_15_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Trojan.Heur.cuY@HPIO3zfb_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d16a64d7c0145ccfa7c0f8a588e3f74f48cbfc62569f8efa7fa4124abef85335"

  strings:
    $s1 = "FIRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}