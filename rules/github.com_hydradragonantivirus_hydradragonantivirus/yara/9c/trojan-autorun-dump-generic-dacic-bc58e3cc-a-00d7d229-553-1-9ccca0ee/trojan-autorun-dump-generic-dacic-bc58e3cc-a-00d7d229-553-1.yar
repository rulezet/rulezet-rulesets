rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_553_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_553_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd566590e3753dbe7e3de6890fb90adbd8072740f3a2da18f0ac83b3a60ac3bf"

  strings:
    $s1 = "kyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}