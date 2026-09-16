rule Trojan_Autorun_Gen_Trojan_Backdoor2_FmZbaKq9kbjb_6_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.FmZbaKq9kbjb_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbba6a50b2deeba3a8486e8f0dd1b6ad1ed7935af8fbdd4bc0596a5e5c9e4bb1"

  strings:
    $s1 = "XBhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}