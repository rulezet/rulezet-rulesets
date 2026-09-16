rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_ayWIjmh_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@ayWIjmh_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b43e2437c634921ad1b7441a4952a17c5551736951841e05956575844080b737"

  strings:
    $s1 = ";your order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}