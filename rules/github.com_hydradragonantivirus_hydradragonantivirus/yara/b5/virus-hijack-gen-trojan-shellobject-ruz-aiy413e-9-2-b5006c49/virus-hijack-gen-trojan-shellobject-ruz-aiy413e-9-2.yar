rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aiy413e_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aiy413e_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d50217185f780dabc7de9a78ce14ed06afd3fb3e8c17e5f0417b484a5165da8"

  strings:
    $s1 = "kernel)V" fullword ascii
    $s2 = "X)w(null" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}