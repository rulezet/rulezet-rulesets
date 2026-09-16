rule Virus_Autorun_Trojan_Ransom_Crysis_E {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Trojan.Ransom.Crysis.E.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e64137a2e27ab7858e29ee878fec4cc428a7ccd84d68d6a9e335dd81ea70a55"

  strings:
    $s1 = "LastErtr#Enter" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}