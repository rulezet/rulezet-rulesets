rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a24b7c609f3ccdbb9e2ac52b249b8abbc9c097be4e7f68d2faea8d186db200f0"

  strings:
    $s1 = "Exception: %X %X %X" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}