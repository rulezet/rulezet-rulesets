rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCMzZah_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCMzZah_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "831a7152e6ef5c747ffae9900467a2ea63e1e90a2ab5d8422953e36d4988ff04"

  strings:
    $s1 = ":orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}