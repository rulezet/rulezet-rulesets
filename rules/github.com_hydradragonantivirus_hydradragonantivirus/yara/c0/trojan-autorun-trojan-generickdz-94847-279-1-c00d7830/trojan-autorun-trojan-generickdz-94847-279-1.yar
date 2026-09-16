rule Trojan_Autorun_Trojan_GenericKDZ_94847_279_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_279_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e13f44d0aedc930c9eec3ef1d1c5aba1c1357e8ee4047d3da94a8f3880cc1182"

  strings:
    $s1 = "cOze Bze" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}