rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_657_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_657_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "278dd76737fd68dc8b4c91af51a17a63e6b80f789fd6ae25f0a2a3d9842873b5"

  strings:
    $s1 = "$are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}