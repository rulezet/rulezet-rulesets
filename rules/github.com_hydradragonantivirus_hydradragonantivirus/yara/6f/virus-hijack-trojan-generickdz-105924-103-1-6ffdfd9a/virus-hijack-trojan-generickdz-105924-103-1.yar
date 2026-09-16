rule Virus_Hijack_Trojan_GenericKDZ_105924_103_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_103_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f2e17c5905fe99ebc827a20eea5fc36283c2f8408f71eff740889bf8321e27e"

  strings:
    $s1 = "Hong}m" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}