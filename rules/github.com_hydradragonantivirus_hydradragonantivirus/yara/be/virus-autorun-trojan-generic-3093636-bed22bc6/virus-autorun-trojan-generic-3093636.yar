rule Virus_Autorun_Trojan_Generic_3093636 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Trojan.Generic.3093636.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98ccda5de1bd23cc49757ca81636be93fc6cb09ded6a273776c819cf2bfa8ae1"

  strings:
    $s1 = "f:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
    $s2 = "explorer " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}