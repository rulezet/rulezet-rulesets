rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_346_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_346_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e284522abad241deb0d69ed1c693719a3898699a9c9bb9f5a810aaa42dfc587b"

  strings:
    $s1 = "ware a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}