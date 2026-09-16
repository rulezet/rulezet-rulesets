rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d61303ad0a04ea6b405bebe6a97c06eb13df498469680d64a8dba6a23702c2df"

  strings:
    $s1 = "mProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}