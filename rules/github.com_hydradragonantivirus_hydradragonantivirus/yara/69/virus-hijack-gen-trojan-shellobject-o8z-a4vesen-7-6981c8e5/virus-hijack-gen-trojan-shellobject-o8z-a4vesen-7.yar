rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_a4vesEn_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@a4vesEn_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fbbe93ae4afc92b6a0fbc8c549a771255356c6f433029c152c08191e19282d7"

  strings:
    $s1 = "`microsoft.com/office/backup. You may not distribute the backup copy of the software. You may use it" fullword ascii
    $s2 = "THOUGH WE DO NOT, YOU CA NNOT RECOVER MORE THA N YOU PAI`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}