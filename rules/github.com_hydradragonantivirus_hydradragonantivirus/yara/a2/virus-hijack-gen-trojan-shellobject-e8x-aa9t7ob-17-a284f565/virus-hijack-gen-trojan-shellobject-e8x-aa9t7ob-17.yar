rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddf71884c1f68d00cb91489905eee0af90c8a78ced5f48e23f76b9e5aab4653a"

  strings:
    $s1 = "9hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}