rule Virus_Hijack_Trojan_GenericKDZ_99416_30 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_30.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "743108e4a5241bab990f4c2e04df26ad3356e7c5ba684e5d29f1de96f473da2b"

  strings:
    $s1 = "rUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}