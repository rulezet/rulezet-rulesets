rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_57_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_57_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46f841c916b20ac5c8b315faf536c05dd58f481ba2ef7c7711c2bcf7799b14d1"

  strings:
    $s1 = "j,of the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}