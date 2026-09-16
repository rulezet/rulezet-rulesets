rule Virus_Hijack_Trojan_GenericKDZ_105924_427 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_427.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21e34260f55030eb301ea2cb58ebb54604e0b47957e3bb949da7a1883eca150d"

  strings:
    $s1 = "Tern Fzp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}