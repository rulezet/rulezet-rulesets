rule Virus_Hijack_Trojan_GenericKDZ_105924_465_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_465_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90cf1ded258899b8b01fc6bcca9ee885784972773ff8c60234b89ba80beab877"

  strings:
    $s1 = "mORG;mY" fullword ascii
    $s2 = "j;ronD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}