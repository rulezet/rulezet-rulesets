rule Trojan_Autorun_Trojan_GenericKDZ_94847_253_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_253_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7b6cacd9b5e38183542e807aa9ab25b2c05f8ff10d498c9b27a2dddfab17ffc"

  strings:
    $s1 = "FIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}