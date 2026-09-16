rule Virus_Hijack_Gen_Trojan_ShellObject_e0X_aaSKtRj_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e0X@aaSKtRj_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87eb58f78a5e319230b73c138131928c2f5e3245d7c32e74c9cbd7239e06dc9e"

  strings:
    $s1 = "Lfunctionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}