rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec84a8af525c2d46daec879879c931bc20a6db3f5f7097cbcea8328d73c4a090"

  strings:
    $s1 = "Qu`hiTcH" fullword ascii
    $s2 = ",MaSs{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}