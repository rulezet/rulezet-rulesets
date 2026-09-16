rule Trojan_Autorun_Gen_Trojan_Backdoor2_fmZbaKq9kbjb_17 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.fmZbaKq9kbjb_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "357095955bb49b3da6447cc0bd534faa1c933fc0f3adf7f2fb2b04858038dad8"

  strings:
    $s1 = "7-Zip 19.00 (x64) is uninstalled" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}