rule Virus_Hijack_Gen_Trojan_ShellObject_e0X_aaSKtRj_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e0X@aaSKtRj_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47f4eef08e3b83d1a88216442c6a068606ceac4a45dc5233daed7b33528c0eca"

  strings:
    $s1 = "[MiFf#=" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}