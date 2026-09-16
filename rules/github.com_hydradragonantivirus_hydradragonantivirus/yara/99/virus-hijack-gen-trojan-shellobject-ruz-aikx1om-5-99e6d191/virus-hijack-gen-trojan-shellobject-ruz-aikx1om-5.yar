rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aikx1Om_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aikx1Om_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c0518858fe6fd020e6b397bf0489404de2ebb74596e1260bfcfb26fa5256e59"

  strings:
    $s1 = "u&letE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}