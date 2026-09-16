rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_ayWIjmh_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@ayWIjmh_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b81f1bd61f873ea1519f8c10804e6f00b79cfc6f21fcc50109eda54f55a8646"

  strings:
    $s1 = "jyour order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}