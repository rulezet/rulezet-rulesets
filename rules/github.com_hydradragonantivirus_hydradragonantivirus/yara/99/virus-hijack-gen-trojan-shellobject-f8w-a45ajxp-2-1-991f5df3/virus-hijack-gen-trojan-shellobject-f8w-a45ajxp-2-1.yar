rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a45ajXp_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a45ajXp_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f849bab8ee416ddf507a8caa4c11a529d9c4c8d59f2b45a252aca2bbbf418825"

  strings:
    $s1 = ".b***Added %BVTAdmin%@37L4247F27-08 to D:\\UserMan.ini" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}