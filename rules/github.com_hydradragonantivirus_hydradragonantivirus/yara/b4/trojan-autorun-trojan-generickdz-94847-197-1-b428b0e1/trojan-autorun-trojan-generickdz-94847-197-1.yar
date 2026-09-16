rule Trojan_Autorun_Trojan_GenericKDZ_94847_197_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_197_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dfc903e27eb78e78d65a5c49d7ed1bb88ac23b6e762fa147a4a9e7bb854094a"

  strings:
    $s1 = " WIRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}