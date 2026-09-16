rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_109_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_109_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d64973ee82661cc1b0b86b77ffa7f2f34f835743feb72297a124d23778168749"

  strings:
    $s1 = "Iare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}