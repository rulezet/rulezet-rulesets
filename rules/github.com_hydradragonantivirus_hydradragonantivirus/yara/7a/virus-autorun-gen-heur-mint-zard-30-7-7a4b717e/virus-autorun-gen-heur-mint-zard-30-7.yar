rule Virus_Autorun_Gen_Heur_Mint_Zard_30_7 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Gen.Heur.Mint.Zard.30_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f165e481cc0a458c2bd341c261a7ee1e91212f0c56a81a43d54d29b805ae940"

  strings:
    $s1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)" fullword ascii
    $s2 = "Error %d when getting local host name." fullword ascii
    $s3 = "Yow! Bad host lookup." fullword ascii
    $s4 = "Thank you for use mh" fullword ascii
    $s5 = "Accept: text/html, application/xhtml+xml, */*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}