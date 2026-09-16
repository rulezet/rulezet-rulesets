rule Virus_Hijack_Trojan_Ransom_Crysis_E_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Ransom.Crysis.E_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4b7b115d3e3100bd9b5305ad73f75f44dc6b1dd824b7f9daae0e5bcaeac1fa9"

  strings:
    $s1 = "^<raTh" fullword ascii
    $s2 = "THoU{l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}