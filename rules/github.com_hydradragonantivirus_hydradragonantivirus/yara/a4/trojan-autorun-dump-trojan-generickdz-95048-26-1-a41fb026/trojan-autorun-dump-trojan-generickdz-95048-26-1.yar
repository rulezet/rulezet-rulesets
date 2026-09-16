rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_26_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_26_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "632f6bd391513778ad8b7423cac69253a5a2b8cb88de1c1430d65c0054f45ae5"

  strings:
    $s1 = "Csoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}