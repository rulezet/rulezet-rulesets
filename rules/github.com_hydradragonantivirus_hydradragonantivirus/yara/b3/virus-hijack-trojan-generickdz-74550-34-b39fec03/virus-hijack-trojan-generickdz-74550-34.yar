rule Virus_Hijack_Trojan_GenericKDZ_74550_34 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_34.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e09bd771ab474b042e59a366b339e276e456e80ca76ff385609a1cf5ec130403"

  strings:
    $s1 = "pATo{AT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}