rule Virus_Hijack_Trojan_GenericKDZ_79663_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa3287e5d982ae5e2ce589a824b0ebf8f2733a74e12966c523c980837c89b705"

  strings:
    $s1 = "1<GyrAL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}