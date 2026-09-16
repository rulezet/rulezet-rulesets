rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_276_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_276_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e93301e996c431fd0742dde4d8f82700b65ae6425dd9d9186400fa22157db0c9"

  strings:
    $s1 = "OIf you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}