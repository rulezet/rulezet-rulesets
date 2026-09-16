rule Trojan_Danger_Trojan_GenericKD_67166905_223_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_223_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41ee7b908120fd3118e84c26040a7d92629c26f9a840794163db7ec003c60638"

  strings:
    $s1 = "m#Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}