rule Virus_Hijack_Trojan_GenericKDZ_105924_506_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_506_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77c27e163b202b24119aee4dbb9dab08afc48126d426d8a7f5a27bd412eba511"

  strings:
    $s1 = " Fair@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}