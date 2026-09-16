rule Virus_Hijack_Trojan_GenericKDZ_99416_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88a371696d452ac83ec17aefe1709430aff252d6439a46abd0209ac695a73801"

  strings:
    $s1 = "pUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}