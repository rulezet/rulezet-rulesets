rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1edd7d75240013931ea3fb3c8d2bc9ae3f4c60534480f450dab18ba8e412c15d"

  strings:
    $s1 = "vaRY`.YYb" fullword ascii
    $s2 = "Thundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}