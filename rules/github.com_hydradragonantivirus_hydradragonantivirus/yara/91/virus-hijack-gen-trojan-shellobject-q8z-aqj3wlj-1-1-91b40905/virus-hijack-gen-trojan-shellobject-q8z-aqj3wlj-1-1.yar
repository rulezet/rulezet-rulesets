rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aqj3wLj_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aqj3wLj_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71548376a2ddba4f169e313e34f415717167a4d809bf46e1eb17d1c462862bcd"

  strings:
    $s1 = "(buRp:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}