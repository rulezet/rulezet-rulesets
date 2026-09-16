rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_aCkwazk_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@aCkwazk_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2de2c8cea241bafc0531f11936c5353f5c8ac48f3946790a006dbe53d36bd3f7"

  strings:
    $s1 = "tHRIp&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}