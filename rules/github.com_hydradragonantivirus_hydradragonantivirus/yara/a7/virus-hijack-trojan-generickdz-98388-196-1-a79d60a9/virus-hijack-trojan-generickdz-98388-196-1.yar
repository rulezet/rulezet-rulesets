rule Virus_Hijack_Trojan_GenericKDZ_98388_196_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_196_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8806df2c9e44a6252f812d5897ee54bd5708e37b4a3f299455223d5b95a6ebd"

  strings:
    $s1 = "YoKe]es" fullword ascii
    $s2 = "7`TwAe" fullword ascii
    $s3 = "zU pizeo6" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}