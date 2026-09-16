rule Trojan_Danger_GenPack_Trojan_GenericKDZ_104643_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_GenPack.Trojan.GenericKDZ.104643_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "936a6d946c1a0586fb7703f20848e814ceb74a0704c213f84057d10bbf9d4888"

  strings:
    $s1 = "/`This agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principl" ascii
    $s2 = "/`This agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principl" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}