rule Virus_Hijack_Trojan_GenericKDZ_98388_68_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_68_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb892fe86014c0bb26a159b581f0444eb30ea9c58e9de34fbe8d2e200204d465"

  strings:
    $s1 = "AJar5K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}