rule Virus_Danger_Gen_Trojan_ShellObject_t8Z_ae0D4Vj {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.t8Z@ae0D4Vj.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41d18a038e586c83ff9fc3754d9865b1fac947de101c71ed784a0505874dfd6a"

  strings:
    $s1 = "4a neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}