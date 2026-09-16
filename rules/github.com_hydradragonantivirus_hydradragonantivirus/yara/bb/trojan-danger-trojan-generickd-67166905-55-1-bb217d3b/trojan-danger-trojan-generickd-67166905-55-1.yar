rule Trojan_Danger_Trojan_GenericKD_67166905_55_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_55_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e58d058079f43d6cb8b20f93fd47fbd15d5b919ca08360bfed88e463131743f"

  strings:
    $s1 = "HSOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}