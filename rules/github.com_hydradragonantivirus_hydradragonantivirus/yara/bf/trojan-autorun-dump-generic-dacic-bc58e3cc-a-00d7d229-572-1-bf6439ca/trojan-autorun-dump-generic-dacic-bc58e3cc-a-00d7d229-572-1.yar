rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_572_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_572_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a87720099a83bbfaaabdba4c9364da41cd5e8da4dba46b0da8b1be96b15a9096"

  strings:
    $s1 = "XUcounted as \"n\" processors. For the Healthcare Transaction Base program, only the processors on which Internet Application" fullword ascii
    $s2 = "student enrolled in your institution counts as 25% of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}