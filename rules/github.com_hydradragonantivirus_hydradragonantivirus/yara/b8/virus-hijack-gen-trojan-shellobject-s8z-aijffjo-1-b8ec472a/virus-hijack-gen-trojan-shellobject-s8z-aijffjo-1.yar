rule Virus_Hijack_Gen_Trojan_ShellObject_s8Z_aiJFfJo_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aiJFfJo_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4f4383dfc07b470adabbf5ed25d5d91ce754ce09a23f4c4b6914644a23a5eb4"

  strings:
    $s1 = "you to install only one copy of the `" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}