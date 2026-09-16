rule Trojan_Autorun_Gen_Trojan_Backdoor2_fmZbaKq9kbjb_18 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.fmZbaKq9kbjb_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cef62a6e684a24d7f74cc430cb64747979e0333b44624bc8cbbf14911377fce"

  strings:
    $s1 = "Hosted Named User: is defined as an individual authorized by " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}