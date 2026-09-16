rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_29_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c534a09f5d234081323268c2b813f9a27ca558353a6db89a6bc67a91403aadb"

  strings:
    $s1 = "dalI`gQ" fullword ascii
    $s2 = "dIf you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}