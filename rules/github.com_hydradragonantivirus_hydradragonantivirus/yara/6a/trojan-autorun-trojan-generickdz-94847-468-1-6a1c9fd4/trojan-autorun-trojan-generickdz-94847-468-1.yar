rule Trojan_Autorun_Trojan_GenericKDZ_94847_468_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_468_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d70df6c3b3b676e228379286f61ab002034b4b3e979c9702ceb01078233db701"

  strings:
    $s1 = "vIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}