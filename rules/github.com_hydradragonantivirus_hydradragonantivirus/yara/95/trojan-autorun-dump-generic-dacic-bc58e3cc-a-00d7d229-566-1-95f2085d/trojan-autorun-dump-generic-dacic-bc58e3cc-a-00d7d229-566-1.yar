rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_566_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_566_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beff34b57efd2c88ede32c1fdf5528683b7567d21ffa0bdcbc426017f95d7484"

  strings:
    $s1 = "^8software manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}