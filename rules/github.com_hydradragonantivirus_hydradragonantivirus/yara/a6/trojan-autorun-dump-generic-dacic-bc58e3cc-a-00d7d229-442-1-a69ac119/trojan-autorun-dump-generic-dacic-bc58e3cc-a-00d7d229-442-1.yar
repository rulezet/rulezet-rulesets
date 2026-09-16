rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_442_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_442_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a6e49f59413a05fc787a804b7de3ee819b38f58eba47330a88436233b2235af"

  strings:
    $s1 = "user minimum tabl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}