rule Virus_Hijack_Trojan_GenericKDZ_98113_98_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_98_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4e9e6099cc63ba1d4bec843efa072e42f38e9ab2781a78272ec7f6da476a3cd"

  strings:
    $s1 = "/T`DIGs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}