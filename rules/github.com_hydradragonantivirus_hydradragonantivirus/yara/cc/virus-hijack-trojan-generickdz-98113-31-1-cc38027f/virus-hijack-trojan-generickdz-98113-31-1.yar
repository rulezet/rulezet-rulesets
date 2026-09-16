rule Virus_Hijack_Trojan_GenericKDZ_98113_31_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc2859c335ab0044f485b21694e928ae01938ee35043d9cecc08a34557bc3df0"

  strings:
    $s1 = "mAzy!yGu" fullword ascii
    $s2 = "duCk$." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}