rule Virus_Hijack_Gen_Trojan_ShellObject_v8Z_a0a9m9p_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v8Z@a0a9m9p_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7a3b8ea221f7873d3b208e11c9d47dbc7180846d893bff3ff8bfd90d9adce85"

  strings:
    $s1 = "Copyright @ Microsoft Corporation" fullword wide
    $s2 = "Windows SDK Installer" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}