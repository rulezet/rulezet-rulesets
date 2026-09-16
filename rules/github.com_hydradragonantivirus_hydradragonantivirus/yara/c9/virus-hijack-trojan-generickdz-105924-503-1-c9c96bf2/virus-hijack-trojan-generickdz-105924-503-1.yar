rule Virus_Hijack_Trojan_GenericKDZ_105924_503_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_503_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c709c7bb6e17a0fe0eca013fc4993354c52345d476685988ec8fb5ea8a8038e5"

  strings:
    $s1 = "#%BINg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}