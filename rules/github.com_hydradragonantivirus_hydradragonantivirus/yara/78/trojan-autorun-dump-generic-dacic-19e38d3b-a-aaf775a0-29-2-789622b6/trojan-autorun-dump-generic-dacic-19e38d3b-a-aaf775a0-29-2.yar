rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_29_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_29_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "434ae802c1886c764320004886c1418ab00fb75aba432e630c03591adb6c7dcc"

  strings:
    $s1 = "sKULP]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}