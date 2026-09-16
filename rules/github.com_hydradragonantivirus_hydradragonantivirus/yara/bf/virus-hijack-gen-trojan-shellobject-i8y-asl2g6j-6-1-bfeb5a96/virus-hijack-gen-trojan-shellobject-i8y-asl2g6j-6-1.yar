rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aSl2g6j_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aSl2g6j_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0bbc262741c8885098c6b4b85b9eaebc063a7d65b4c1f7bbb381520bbfc7382"

  strings:
    $s1 = "B_controlfp_s(((void *)0), 0x00010000, 0x00030000)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}