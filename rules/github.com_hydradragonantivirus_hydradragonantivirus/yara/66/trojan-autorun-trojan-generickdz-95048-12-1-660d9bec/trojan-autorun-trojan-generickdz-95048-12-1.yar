rule Trojan_Autorun_Trojan_GenericKDZ_95048_12_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.95048_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f37aa7b4f48fc4108f7e69494178e7b09bff160cc0b6bddedce1699ad56297d"

  strings:
    $s1 = "1Jwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}