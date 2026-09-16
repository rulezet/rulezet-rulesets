rule Virus_Hijack_Backdoor_Hangup_B_284_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_284_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "095116ecd97572b3b76513ebbca09d31a9b4cf04c9fff4e3e47282cca2936d1e"

  strings:
    $s1 = "Examples of these features include clip art, templates, online training, onlix8nvoj051u98i4iuri853dj2xlj708t7w7eg10q2u7e96usm248" ascii
    $s2 = "Examples of these features include clip art, templates, online training, onlix8nvoj051u98i4iuri853dj2xlj708t7w7eg10q2u7e96usm248" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}