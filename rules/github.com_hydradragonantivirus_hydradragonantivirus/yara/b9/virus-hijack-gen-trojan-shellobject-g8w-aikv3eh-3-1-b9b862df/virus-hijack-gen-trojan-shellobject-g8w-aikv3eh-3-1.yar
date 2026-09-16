rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiKV3eh_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiKV3eh_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12bb25ef1a2b4e1b253809de0b4f34262e3520b381048fc8e15c46e864aec8b3"

  strings:
    $s1 = "TypeScript Keyboard Sync.exe" fullword wide
    $s2 = "TypeScript Keyboard Sync" fullword wide
    $s3 = " TypeScript Keyboard Sync 2017" fullword wide
    $s4 = "Keyboard Sync 1.0" fullword wide
    $s5 = "Index settings" fullword wide
    $s6 = "alid credential persistence." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}