rule Trojan_Autorun_Trojan_GenericKDZ_94847_453_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_453_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c4d7c3ed37947c796e8ba3fa677e064c0148103989000d212bedbef5494a8e5"

  strings:
    $s1 = "5IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}