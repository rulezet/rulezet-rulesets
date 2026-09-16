rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_249_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_249_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e52ed47d5f6e5653a80847b1acef673014d17f1580bbc05d22cc7a958ba5c56"

  strings:
    $s1 = "noTed!" fullword ascii
    $s2 = "rOLe?R" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}