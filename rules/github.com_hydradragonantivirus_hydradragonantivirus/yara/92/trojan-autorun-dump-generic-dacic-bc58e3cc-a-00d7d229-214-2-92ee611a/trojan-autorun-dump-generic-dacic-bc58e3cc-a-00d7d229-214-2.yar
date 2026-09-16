rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_214_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_214_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85abd3c96432231ba96dc2e5d85fdf438ec742f5fe6578c72c9cbe500b88668f"

  strings:
    $s1 = "Gisarme Narkier Inc.1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}