rule Trojan_Autorun_Trojan_GenericKDZ_94847_366_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_366_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b86d3a78b86e414e1ae9c58ccb10a1d8761bf046808580eef449ef3bced907b5"

  strings:
    $s1 = "4IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}