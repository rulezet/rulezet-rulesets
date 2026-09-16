rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_631_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_631_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "175fdbd2546df1d2494509cdb4725fc3b7a8ee77baf0ac87b593fd86078050d9"

  strings:
    $s1 = "active employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}