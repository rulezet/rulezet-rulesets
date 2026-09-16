rule Trojan_Autorun_Trojan_GenericKD_72517131_109_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_109_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f61d8fbc46f208867b794d363744c5a089c0fecde878a96bebc76232ef2db411"

  strings:
    $s1 = "BUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}