rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_320_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_320_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7443e4c136f134aaa92b56dc7231e37afff7ec75fa6a91bb84f65f3a4f21c97c"

  strings:
    $s1 = ")Resource instance not specified, did you call CommonLibraryDllProcessAttach?" fullword ascii
    $s2 = "c;rAVe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}