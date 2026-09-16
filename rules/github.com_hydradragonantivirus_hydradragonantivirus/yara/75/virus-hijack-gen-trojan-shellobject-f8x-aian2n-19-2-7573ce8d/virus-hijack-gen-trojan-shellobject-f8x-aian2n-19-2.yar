rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_19_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_19_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3691c5f1d006bc754cccc4f9bfbcce8cf0268448794a86670ced7dea3eade810"

  strings:
    $s1 = "@soft Visual Studio\\VB98;C:\\Windows\\system32;C:\\Windows\\system;" fullword wide
    $s2 = "EyC:\\Program Files\\Microsoft Visual Studio\\VB98\\Wizards\\CHARTWIZ.oca" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}