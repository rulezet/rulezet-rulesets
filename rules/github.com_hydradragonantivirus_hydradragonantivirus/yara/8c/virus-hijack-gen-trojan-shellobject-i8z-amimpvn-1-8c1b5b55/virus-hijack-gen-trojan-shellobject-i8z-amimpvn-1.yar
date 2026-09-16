rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_amIMPvn_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amIMPvn_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b56f90556a1dd47ccae75cf310568e5474aa7e1078739e2b8efe0a6ee4e68358"

  strings:
    $s1 = "kpolicy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}