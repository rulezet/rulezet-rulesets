rule Trojan_Autorun_Trojan_GenericKDZ_94847_126_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_126_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99cb24ab3af47340d0433cf538ddc35c1fc864567bdcbce3f2bfb9211cc8c5b1"

  strings:
    $s1 = ")Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}