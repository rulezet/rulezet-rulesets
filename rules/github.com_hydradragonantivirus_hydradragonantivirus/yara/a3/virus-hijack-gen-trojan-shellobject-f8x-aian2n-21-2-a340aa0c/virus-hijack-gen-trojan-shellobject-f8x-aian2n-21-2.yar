rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_21_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_21_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cee361d706d503a4ad71e7f5a1caac41364fa085ea25aa38d03979968dde6a3e"

  strings:
    $s1 = "EyC:\\Program Files\\Microsoft Visual Studio\\VB98\\Wizards\\CHARTWIZ.oca" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}