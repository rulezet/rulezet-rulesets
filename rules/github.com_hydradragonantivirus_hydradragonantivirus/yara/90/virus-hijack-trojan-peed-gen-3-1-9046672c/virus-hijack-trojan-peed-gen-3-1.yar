rule Virus_Hijack_Trojan_Peed_Gen_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4ce03df2e63608faf1517f01ae46ed032daa31afde5e4f69eae2269b95257c3"

  strings:
    $s1 = "MINk:uO" fullword ascii
    $s2 = "] KICk" fullword ascii
    $s3 = "c)luNt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}