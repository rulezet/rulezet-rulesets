rule Virus_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f346b4571f22431a9875891d5538a23cfdc6aa656e85122c3acd7b3e0c3c6ed"

  strings:
    $s1 = "TRap?<nau" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}