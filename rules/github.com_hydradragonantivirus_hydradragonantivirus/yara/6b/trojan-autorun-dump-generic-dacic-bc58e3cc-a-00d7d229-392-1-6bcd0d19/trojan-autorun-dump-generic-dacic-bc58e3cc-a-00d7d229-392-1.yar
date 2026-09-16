rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_392_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_392_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f7eb3e0523674d4f33dd5ebebac7e99ba75137138e8d3d3b5b2d5dd8d0521b4"

  strings:
    $s1 = "must be a Qualified Educational User to use soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}