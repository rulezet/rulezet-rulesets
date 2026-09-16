rule Trojan_Autorun_Gen_Trojan_Backdoor2_gmZbaKq9kbjb_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.gmZbaKq9kbjb_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91d6a5ae1ac78b16910d6b1758f2c72a71d639cffeef8b4441971e9ed4de731e"

  strings:
    $s1 = "K])TOHo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}