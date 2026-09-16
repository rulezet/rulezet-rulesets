rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2bf5d24dec658fcc2efb8573597a3260081882f7559f9eee204ec1596cf269d"

  strings:
    $s1 = "+Phundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}