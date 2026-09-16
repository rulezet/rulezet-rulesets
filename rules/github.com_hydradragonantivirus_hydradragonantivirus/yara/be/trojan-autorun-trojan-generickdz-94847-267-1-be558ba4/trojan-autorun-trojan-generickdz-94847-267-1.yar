rule Trojan_Autorun_Trojan_GenericKDZ_94847_267_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_267_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e76dbf5707354ca51a9252561f9da2b2bbb2838e9326f04e2c461af60505104d"

  strings:
    $s1 = "jIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}