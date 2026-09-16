rule Trojan_Autorun_Gen_Trojan_Backdoor2_HmZbaKq9kbjb_9_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.HmZbaKq9kbjb_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc10ada726bbe22abd641ac89e033aea8e8ceef697ed4b49e7a31d1a1d7161a9"

  strings:
    $s1 = "54. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}