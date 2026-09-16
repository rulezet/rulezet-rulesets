rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_661_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_661_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b13982c8d5d8155f66b27925b674de43575b782a25f884f3c6b1873c40d9892f"

  strings:
    $s1 = "Bcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}