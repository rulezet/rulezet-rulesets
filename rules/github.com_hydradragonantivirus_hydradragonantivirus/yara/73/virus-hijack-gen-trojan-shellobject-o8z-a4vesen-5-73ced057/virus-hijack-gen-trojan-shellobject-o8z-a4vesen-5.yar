rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_a4vesEn_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@a4vesEn_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bc12eca44816ebb089292a0129418230e25d511021d9cc883ef83f8610ff47a"

  strings:
    $s1 = "Dmicrosoft.com/office/backup. You may not distribute the backup copy of the software. You may use it" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}