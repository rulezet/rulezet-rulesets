rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_23_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d489f6689bca885ec09f30e2e342f941470d66db623883b605303c885b115065"

  strings:
    $s1 = "Exception: %X %X %X" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}