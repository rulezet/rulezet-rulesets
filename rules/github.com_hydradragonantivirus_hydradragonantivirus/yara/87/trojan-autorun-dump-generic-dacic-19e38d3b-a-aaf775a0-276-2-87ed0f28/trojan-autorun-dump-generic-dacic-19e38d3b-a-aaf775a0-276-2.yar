rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_276_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_276_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78c5e3d4ee3ed7bb6a2db01792a83d127e3ab5bf6d3274501b258ad564de2ce4"

  strings:
    $s1 = "stEG  " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}