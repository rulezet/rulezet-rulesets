rule Virus_Sysbot_Trojan_GenericKD_61340032_2 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.61340032_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78cedb9c4d7e9414f68679d99c104ab034abcffe2577304abb7a1f4d9c41a099"

  strings:
    $s1 = "!Th D program cannot be run in DOS mode." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}