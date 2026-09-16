rule Virus_Danger_Trojan_Peed_Gen_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.Peed.Gen_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d60338727ba931da1bcf2fc3a2927faed00ba92d7a9d6b8b86771db8266ad04"

  strings:
    $s1 = "Python 3.11 Module Docs (64-bit).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}