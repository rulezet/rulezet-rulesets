rule Virus_Hijack_Trojan_GenericKDZ_98388_83 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_83.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57fb73f13e5b584e3a5679a5c0b3c10d6d355d1ff2be2f23af98a775ec175138"

  strings:
    $s1 = "`month pe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}