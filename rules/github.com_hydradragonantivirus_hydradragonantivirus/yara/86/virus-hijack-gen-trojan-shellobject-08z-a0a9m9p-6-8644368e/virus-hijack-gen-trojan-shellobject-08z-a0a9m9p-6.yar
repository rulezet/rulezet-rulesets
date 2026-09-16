rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_a0a9m9p_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2888fb7b6138f67b395c71338a06bb18881b8b6acb75cf5c09a5d86dc95c854"

  strings:
    $s1 = "\"Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}