rule Virus_Hijack_Gen_Trojan_ShellObject_e0X_aaSKtRj_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e0X@aaSKtRj_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b38e7bd438bf340f25d0a085db542e8504834533ad59606861e503861b6bc923"

  strings:
    $s1 = "y]functionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}