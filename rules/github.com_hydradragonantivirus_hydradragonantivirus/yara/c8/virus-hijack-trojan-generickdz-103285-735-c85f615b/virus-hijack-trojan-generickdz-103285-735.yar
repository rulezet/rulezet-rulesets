rule Virus_Hijack_Trojan_GenericKDZ_103285_735 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_735.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "277ab1114b2fff9aefa3d881bc40c7a603fa7f08d8567cfb08f43fae69070915"

  strings:
    $s1 = "gvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}