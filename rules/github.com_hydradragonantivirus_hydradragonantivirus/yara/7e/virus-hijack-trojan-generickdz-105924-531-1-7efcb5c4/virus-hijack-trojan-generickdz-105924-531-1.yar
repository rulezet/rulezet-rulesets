rule Virus_Hijack_Trojan_GenericKDZ_105924_531_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_531_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a30af8e9cc19b19b087143ac562c0466f881f2351b2752a46c2f8d4235489a3"

  strings:
    $s1 = "#fIvE%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}