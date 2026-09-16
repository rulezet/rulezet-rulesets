rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_398_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_398_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fc40617d7d72235ce482abe9ca3febc924824cb8e2dd61c11b866a4653cef74"

  strings:
    $s1 = "Microsoft Ireland Operations Limited makes the limited warranty. To make a claim unde" fullword ascii
    $s2 = "<@kiEL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}