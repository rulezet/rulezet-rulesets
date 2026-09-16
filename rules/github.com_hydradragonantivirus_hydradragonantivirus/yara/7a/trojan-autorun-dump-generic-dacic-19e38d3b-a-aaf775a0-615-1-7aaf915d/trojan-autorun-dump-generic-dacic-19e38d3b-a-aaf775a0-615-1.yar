rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_615_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_615_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af2d496d5496c6b5ca7ea38db508281f6fbe098528d53250ef7856865bf50211"

  strings:
    $s1 = "you to install only one copy of the `" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}