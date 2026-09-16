rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "187b99015b4b698a7c8e7b5734dfd625a18016081ab59bf983be17e6727c5692"

  strings:
    $s1 = "kDwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}