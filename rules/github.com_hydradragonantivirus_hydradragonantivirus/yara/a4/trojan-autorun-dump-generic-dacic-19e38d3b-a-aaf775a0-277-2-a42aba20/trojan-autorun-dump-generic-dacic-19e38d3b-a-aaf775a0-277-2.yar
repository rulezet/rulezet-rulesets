rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_277_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_277_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dddb999f774d7c62a8e6e6340b2de9d516c6b5f1bf8a26a7e5a849cceaf72c4e"

  strings:
    $s1 = "8 lurE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}