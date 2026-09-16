rule Virus_Hijack_Gen_Trojan_ShellObject_oSZ_aaT6Wyj {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oSZ@aaT6Wyj.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "457cf59cbdb04b85cfd28388858e2f51abe9545ea0d999e32ffbb59125638cbb"

  strings:
    $s1 = "8whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}