rule Virus_Hijack_Trojan_GenericKDZ_98113_87_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_87_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3c7906751ca65a0f0ac0fd7656e8489117a6afeb07131d36db2ed0b67da1e48"

  strings:
    $s1 = "K+!Whet" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}