rule Trojan_Autorun_Gen_Trojan_Backdoor2_zmZbaKq9kbjb_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.zmZbaKq9kbjb_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f08a86aa85663b91531fb8d4813c4a44cfa81904cca5b63887345659a9338de9"

  strings:
    $s1 = "CP!bARM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}