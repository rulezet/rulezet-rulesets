rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_243_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_243_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07450716f2f385f4b7f9ddc42b533a8a907f12b2ff3aa6bb6dd9aed63c9caa19"

  strings:
    $s1 = "B)YAWN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}