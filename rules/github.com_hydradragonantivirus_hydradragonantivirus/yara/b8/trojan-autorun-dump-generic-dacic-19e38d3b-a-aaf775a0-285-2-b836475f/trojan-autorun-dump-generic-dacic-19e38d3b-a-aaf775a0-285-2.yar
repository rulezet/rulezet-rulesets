rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_285_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_285_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb4e5d27b6084f6af14bc43c3c195f1a2ec49890aec99b1f00df317f2c4cd9e8"

  strings:
    $s1 = "\\}jAtO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}