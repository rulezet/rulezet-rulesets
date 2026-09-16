rule Virus_Hijack_Gen_Trojan_ShellObject_luZ_amBwvTb_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.luZ@amBwvTb_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e25e0dbccd24bf57c38fa937d402379e41ee16d9f440fa360c221e92c7fe3ef8"

  strings:
    $s1 = "<Module>{C041348C-ED52-4FA5-9E5E-3B4E80C89E15}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}