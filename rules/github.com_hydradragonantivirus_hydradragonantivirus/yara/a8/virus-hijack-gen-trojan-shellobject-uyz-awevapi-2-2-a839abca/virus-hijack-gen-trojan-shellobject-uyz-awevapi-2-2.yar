rule Virus_Hijack_Gen_Trojan_ShellObject_uyZ_aWevApi_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uyZ@aWevApi_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "960ee22ed8914e6907b4427aa27bcf64234e5d10288da1d9beb09a5ed735eb52"

  strings:
    $s1 = "Copyright 2011 Adobe Systems Incorporated" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}