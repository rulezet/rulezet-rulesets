rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_153_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_153_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07019b60b4960759ee19d88d4874dfc1a54fea5823b154e9aacc1e5f290478a9"

  strings:
    $s1 = "xpected multithread lock error" fullword wide
    $s2 = "  (fc_2): Linear(in_features=256, out_features=" fullword ascii
    $s3 = "  (fc_1): Linear(in_features=256, out_features=256, bias=True)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}