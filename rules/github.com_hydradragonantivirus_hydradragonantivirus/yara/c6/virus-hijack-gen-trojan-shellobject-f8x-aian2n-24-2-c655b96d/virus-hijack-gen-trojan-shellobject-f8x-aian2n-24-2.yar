rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_24_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_24_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50366de1e9fcb6b2ec8640f63f864917edeac33fd4185245ddb844bde37fcc76"

  strings:
    $s1 = "@soft Visual Studio\\VB98;C:\\Windows\\system32;C:\\Windows\\system;" fullword wide
    $s2 = "EyC:\\Program Files\\Microsoft Visual Studio\\VB98\\Wizards\\CHARTWIZ.oca" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}