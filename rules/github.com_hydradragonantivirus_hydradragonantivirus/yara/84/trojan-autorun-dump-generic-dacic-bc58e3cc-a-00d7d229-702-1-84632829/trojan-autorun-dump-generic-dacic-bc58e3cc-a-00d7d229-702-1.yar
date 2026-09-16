rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_702_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_702_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bddc821de2b70cf64496fedc27695dc8444b5f38aa81f17317f036fcc3253dba"

  strings:
    $s1 = "=iof the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}