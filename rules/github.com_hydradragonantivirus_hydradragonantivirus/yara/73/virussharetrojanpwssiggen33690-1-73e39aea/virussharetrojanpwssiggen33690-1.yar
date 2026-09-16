rule VirusShareTrojanPWSSiggen33690_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPWSSiggen33690_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0f0dfd92934d4fd1b6f496319d2f2ae4afffd0805b8b47c6be7b23d04026e21"

  strings:
    $s1 = "Insidious" fullword ascii  
    $s2 = "FuckTheSystem Copyright " fullword wide
    $s3 = " FuckTheSystem Copyright " fullword ascii
    $s4 = "44 CALIBER" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}