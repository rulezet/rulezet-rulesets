rule Virus_Hijack_Trojan_GenericKDZ_94849_38_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_38_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf60ba24ed96fadc656c822f8c496b8e884565137f90d55affc329f0dcd66d4d"

  strings:
    $s1 = "BOZo}w" fullword ascii
    $s2 = "Yc;HusK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}