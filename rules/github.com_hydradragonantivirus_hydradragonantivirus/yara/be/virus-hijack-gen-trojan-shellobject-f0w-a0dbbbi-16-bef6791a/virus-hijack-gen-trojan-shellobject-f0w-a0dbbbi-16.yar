rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10d000c1e1c5ff23fb6344f1f2d5962a9b19d80b92628273508b75fa7a484b5e"

  strings:
    $s1 = "mdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}