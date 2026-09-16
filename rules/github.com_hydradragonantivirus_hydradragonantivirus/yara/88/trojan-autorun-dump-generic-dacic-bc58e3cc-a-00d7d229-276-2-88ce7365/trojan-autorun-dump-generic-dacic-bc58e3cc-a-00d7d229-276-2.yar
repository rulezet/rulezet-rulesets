rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_276_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_276_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24947721f59a0ce3e171f32a33182005a857a2a67c78a28f6303a5d56b3fef58"

  strings:
    $s1 = "Giz kodota tiziwibumap<Pegis lul jefimiwifeyopud remosacuhuyige cimeganoregiwu cuya" fullword wide
    $s2 = "uNCI{K-" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}