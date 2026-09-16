rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_29 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_29.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1305c44cf1fe8f5a5bee011c190a1d8b9ba50c37ddcb183672a762935428202"

  strings:
    $s1 = "xiProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}