rule Trojan_Danger_Trojan_GenericKD_67269844_53_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67269844_53_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7000f84ff32e2308ea49ce39b33ebdbe613ab010737371b559210a7f25e6759a"

  strings:
    $s1 = "4What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}