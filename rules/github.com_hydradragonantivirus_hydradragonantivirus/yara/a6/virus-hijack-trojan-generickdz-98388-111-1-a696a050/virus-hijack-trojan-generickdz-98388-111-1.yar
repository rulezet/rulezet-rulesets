rule Virus_Hijack_Trojan_GenericKDZ_98388_111_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_111_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8cf56e53732ae663806f3cf10960e399399e197e45d73b2608a984c4764f8d"

  strings:
    $s1 = "L<[Thaw" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}