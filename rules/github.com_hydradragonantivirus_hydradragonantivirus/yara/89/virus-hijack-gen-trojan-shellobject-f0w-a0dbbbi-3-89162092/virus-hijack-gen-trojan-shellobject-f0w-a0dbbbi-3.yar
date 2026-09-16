rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fdba780a3bc0829cc17e74dc5543e79a7628bf00c5aed70aef239c81a1c2d02"

  strings:
    $s1 = "WOdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii
    $s2 = "CrIb:d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}