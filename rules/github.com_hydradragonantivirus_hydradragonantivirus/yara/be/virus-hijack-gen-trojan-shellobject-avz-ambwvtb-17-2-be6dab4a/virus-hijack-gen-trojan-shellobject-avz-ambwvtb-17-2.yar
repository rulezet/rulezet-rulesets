rule Virus_Hijack_Gen_Trojan_ShellObject_avZ_amBwvTb_17_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.avZ@amBwvTb_17_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "035373a454afd283da27ebf569ab355be7db470a1a30c3695e18c984b785e1f8"

  strings:
    $s1 = " 2015 - 2017 Jan Karger, Bastian Schmidt, James Willock" fullword wide
    $s2 = ".NET Framework 4.5r" fullword ascii
    $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36" fullword wide
    $s4 = "Copyright (C) 2021 EXEASY" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}