rule Virus_Hijack_Trojan_GenericKDZ_74550_118_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_118_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfb5dcf2705b08f0bfc77683d409324bcd47d1f6c9f049d38e1b926eff93d2fd"

  strings:
    $s1 = "[@<Gale" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}