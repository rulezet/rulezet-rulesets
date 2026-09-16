rule Virus_Hijack_Gen_Trojan_ShellObject_luZ_amBwvTb_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.luZ@amBwvTb_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38713c63b74ba3afb802be57aae6a4563b8127e9ad4337f0c1bb971df82c920b"

  strings:
    $s1 = "<Module>{C041348C-ED52-4FA5-9E5E-3B4E80C89E15}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}