rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_88_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_88_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddc8e5a503d6e463e1c57ab609bba26bff211c99f34001bc8f23fa285f1b7f3b"

  strings:
    $s1 = "\"software manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}