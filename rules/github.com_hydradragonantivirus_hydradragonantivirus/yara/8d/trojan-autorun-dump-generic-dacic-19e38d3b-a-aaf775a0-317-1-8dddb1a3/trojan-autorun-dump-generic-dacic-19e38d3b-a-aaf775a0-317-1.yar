rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_317_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_317_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceeda61c6b2f1d65e10f8a870f9558647da7fa709b0ffbe735550a3ee15d6a22"

  strings:
    $s1 = "you to install only one copy of the `" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}