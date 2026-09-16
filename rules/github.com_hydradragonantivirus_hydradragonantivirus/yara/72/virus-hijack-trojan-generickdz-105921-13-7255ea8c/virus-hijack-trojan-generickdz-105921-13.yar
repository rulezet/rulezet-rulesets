rule Virus_Hijack_Trojan_GenericKDZ_105921_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105921_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4f0ebae3369b3e0a3393344ee47479312bef5b4f6486ec7732309009f28d603"

  strings:
    $s1 = "(12013 software. For your convenience, we" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}