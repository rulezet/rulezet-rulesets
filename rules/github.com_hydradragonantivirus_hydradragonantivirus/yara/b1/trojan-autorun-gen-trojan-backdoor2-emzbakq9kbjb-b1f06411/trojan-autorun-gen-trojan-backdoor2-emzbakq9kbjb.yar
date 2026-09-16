rule Trojan_Autorun_Gen_Trojan_Backdoor2_emZbaKq9kbjb {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.emZbaKq9kbjb.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91f994b4737b6163a61bb78e023b3d29c9f70e4049a185cc48a1db990497af1a"

  strings:
    $s1 = "7-Zip 19.00 (x64) is uninstalled" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}