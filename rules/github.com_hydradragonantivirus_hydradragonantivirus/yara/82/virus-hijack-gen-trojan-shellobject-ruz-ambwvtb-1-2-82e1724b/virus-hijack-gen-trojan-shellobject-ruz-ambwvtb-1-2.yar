rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_amBwvTb_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@amBwvTb_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca416b424dff4ed4a9adfd2852f0b4cca2fe050950a5fa522a9cc35964dc7dc2"

  strings:
    $s1 = "kernel)V6" fullword ascii
    $s2 = "p@gram {!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}