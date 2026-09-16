rule Virus_Hijack_Trojan_GenericKDZ_79663_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "230d59e660098de059c20745f7d0e33bd55bb9cc6a423f1820e8bc7df28ebbfe"

  strings:
    $s1 = "mOGo#1" fullword ascii
    $s2 = "MOLT'e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}