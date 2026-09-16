rule Virus_Hijack_Trojan_GenericKDZ_74550_314_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_314_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "172c453c413fa83cf2d0ffad8889f82357e04307367c9b71cded87bf6c180244"

  strings:
    $s1 = "\"LopE;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}