rule Virus_Hijack_Trojan_GenericKDZ_98388_224_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_224_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39586859b083b3063b6f66750d0ffe8e57eef72e202ef10b3082b02a49e77df1"

  strings:
    $s1 = "4^N]%MACk:" fullword ascii
    $s2 = "iNky<<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}