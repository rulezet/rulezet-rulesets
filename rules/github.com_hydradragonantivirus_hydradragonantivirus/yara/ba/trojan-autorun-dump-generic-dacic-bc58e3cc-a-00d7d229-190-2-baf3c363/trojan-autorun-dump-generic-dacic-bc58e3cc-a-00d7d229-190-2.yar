rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_190_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_190_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8115092166a127ff788b835524003b8a7847a274e3647bcd67a20de465b819c8"

  strings:
    $s1 = "hizZ<h" fullword ascii
    $s2 = "ct?UIlY" fullword ascii
    $s3 = "RAUk>i" fullword ascii
    $s4 = "{[}rEEF" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}