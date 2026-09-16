rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d6b24a44bfe2fb00dd3c7140e86ba81429727fc8f8a37d61e24920f908f2b99"

  strings:
    $s1 = "Microsoft Office Word 97-2003 " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}