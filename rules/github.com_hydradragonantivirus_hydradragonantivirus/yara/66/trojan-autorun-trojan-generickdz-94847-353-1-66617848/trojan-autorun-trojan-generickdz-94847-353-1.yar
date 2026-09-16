rule Trojan_Autorun_Trojan_GenericKDZ_94847_353_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_353_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e313abf35bd2144af6bfaae71a48e7fc32f81b09ea05b7b17ea7e086e1caf5fb"

  strings:
    $s1 = "WIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}