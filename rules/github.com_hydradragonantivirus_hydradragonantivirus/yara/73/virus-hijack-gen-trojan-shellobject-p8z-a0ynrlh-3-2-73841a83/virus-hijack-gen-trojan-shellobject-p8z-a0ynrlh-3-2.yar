rule Virus_Hijack_Gen_Trojan_ShellObject_p8Z_a0YNrLh_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8Z@a0YNrLh_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1564f453ac21fd3d2544ea2a80d6b9b11321a9e06d40ec2a4675fe8a7944a79d"

  strings:
    $s1 = "bVisible in Windows API, but not in MFT or directory index." fullword wide
    $s2 = "`::$DATA" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}