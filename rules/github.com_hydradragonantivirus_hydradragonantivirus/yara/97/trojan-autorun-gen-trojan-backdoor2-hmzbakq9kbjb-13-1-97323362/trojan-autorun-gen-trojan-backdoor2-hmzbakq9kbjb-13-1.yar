rule Trojan_Autorun_Gen_Trojan_Backdoor2_HmZbaKq9kbjb_13_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.HmZbaKq9kbjb_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42994c5efe1e4bde9c9748f52d0f24ca637dde295ee78ccfef1d778c96c162ed"

  strings:
    $s1 = "^$4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}