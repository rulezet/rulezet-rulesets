rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_amWqEpo_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@amWqEpo_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e396c869d79d5085b9024bcd65226f170966536f5f442e47f93c6cf88e1fabc6"

  strings:
    $s1 = "L]SlAD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}