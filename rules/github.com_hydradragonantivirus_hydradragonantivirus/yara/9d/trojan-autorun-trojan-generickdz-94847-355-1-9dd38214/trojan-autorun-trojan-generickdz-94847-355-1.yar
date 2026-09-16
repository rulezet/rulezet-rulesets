rule Trojan_Autorun_Trojan_GenericKDZ_94847_355_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_355_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "841358e484599656e6651359cb5b13a123b971a5c193a5183c428d38cb441e8d"

  strings:
    $s1 = "5whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}