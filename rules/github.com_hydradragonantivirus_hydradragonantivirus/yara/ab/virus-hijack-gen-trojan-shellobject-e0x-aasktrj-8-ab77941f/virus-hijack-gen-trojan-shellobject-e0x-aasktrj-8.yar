rule Virus_Hijack_Gen_Trojan_ShellObject_e0X_aaSKtRj_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e0X@aaSKtRj_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2775bfa3bbb803d8ef263d8aba7cb1862d658eb602e212a46fb577b5efeddf24"

  strings:
    $s1 = "Nfunctionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}