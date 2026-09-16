rule Virus_Hijack_Trojan_GenericKDZ_105924_537 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_537.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eeadd7edb7ae171ef78df0c34f46e7c70aa86b2e01e23b7a78ed7bc0964ba962"

  strings:
    $s1 = "auLd?+" fullword ascii
    $s2 = "\"u$HauL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}