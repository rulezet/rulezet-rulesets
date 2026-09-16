rule Trojan_Autorun_Trojan_GenericKDZ_94847_464_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_464_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "861545460db0090617cb7fdfe1d89e28c07516f64c3126caca29d1c9686684d7"

  strings:
    $s1 = " Rorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}