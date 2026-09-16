rule VirusShareTrojanSiggen1961528_7 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1961528_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e59150e5c2e49772bb573492df8dd17cff30f78b23bc2574d8c19dab1551cf40"

  strings:
    $s1 = "\"Gogo1000 Was Here! Disc: gogo#3940" fullword ascii
    $s2 = "Gogo1000 Was Also Here" fullword ascii
    $s3 = "1Gogo1000 Was Also Here.o1Biz_>pVv0{%IK\\&zCz$yq{R'" fullword ascii
    $s4 = "\"Btw dont try to deobfuscate pls :(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}