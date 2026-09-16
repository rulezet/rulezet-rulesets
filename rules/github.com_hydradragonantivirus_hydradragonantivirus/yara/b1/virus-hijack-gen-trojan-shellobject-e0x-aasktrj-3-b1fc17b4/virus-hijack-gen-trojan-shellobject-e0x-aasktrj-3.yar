rule Virus_Hijack_Gen_Trojan_ShellObject_e0X_aaSKtRj_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e0X@aaSKtRj_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c9aeebefa467e453a9b48c19aed415f0fb5ea94b50e869498d9cefe97abaadc"

  strings:
    $s1 = "functionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}