rule Trojan_Autorun_Gen_Trojan_Backdoor2_HmZbaKq9kbjb_7_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.HmZbaKq9kbjb_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab6c0380fcd5098e41714cdfc9a873a348ac81fc30bbe635e3719e244b9e1b3c"

  strings:
    $s1 = "Vfunctionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}