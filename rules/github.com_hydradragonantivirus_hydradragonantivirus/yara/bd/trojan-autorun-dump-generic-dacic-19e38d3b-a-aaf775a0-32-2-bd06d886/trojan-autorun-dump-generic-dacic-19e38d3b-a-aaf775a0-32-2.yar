rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_32_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_32_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b90e74698c620363c7b3092192fa943cd6d13c7727f1eb0ece6d0c370f614899"

  strings:
    $s1 = "A8{mEWL@hR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}