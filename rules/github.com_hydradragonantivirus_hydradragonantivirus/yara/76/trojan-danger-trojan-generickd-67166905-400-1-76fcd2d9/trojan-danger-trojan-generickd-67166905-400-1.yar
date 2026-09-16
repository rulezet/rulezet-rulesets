rule Trojan_Danger_Trojan_GenericKD_67166905_400_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_400_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1090fb4c2fcbe15889b9b5c2925ab52e32dea191ed3bab2b3e0dcefd09945d57"

  strings:
    $s1 = "\"Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}