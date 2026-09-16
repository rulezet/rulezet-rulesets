rule Trojan_Autorun_Trojan_GenericKDZ_94847_447_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_447_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ce2e9d56e240bfd2476dfb1f5e078c7ffbffcc6c8df25e99d4bc9ea55f3dc36"

  strings:
    $s1 = "9whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}