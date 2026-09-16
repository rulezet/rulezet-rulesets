rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13532c8fc0ac1f25198ea5ab9152048a09d6b97b5601502ca702569bf16ad53e"

  strings:
    $s1 = "Sdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}