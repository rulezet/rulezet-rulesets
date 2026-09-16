rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_a4YD_Xe_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6fbaa37f8946a214d29c8d58336c0b86ddbc9e8ddd27f3dea02ac09a30e872d"

  strings:
    $s1 = "dynamic method does not support fault clause" fullword wide
    $s2 = "Laragon - fast & powerful local development environment     " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}