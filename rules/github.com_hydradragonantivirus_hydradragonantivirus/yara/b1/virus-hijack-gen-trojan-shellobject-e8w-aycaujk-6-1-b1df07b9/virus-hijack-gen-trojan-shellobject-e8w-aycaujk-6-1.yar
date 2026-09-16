rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f919979d62dc7d278a89c20a73367c97629ce89219c55052383b1df36a88e4e"

  strings:
    $s1 = "<Module>{96BB93E9-D65E-44AB-8BF5-875AC18472A5}" fullword ascii
    $s2 = "t\"EOaN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}