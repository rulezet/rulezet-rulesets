rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe50b1a4b985de5b0a9c118e71e45a92b9b95cc97b45f3e1f4fa2c2f4af87cbf"

  strings:
    $s1 = "Copyright (C) Buidgtre" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}