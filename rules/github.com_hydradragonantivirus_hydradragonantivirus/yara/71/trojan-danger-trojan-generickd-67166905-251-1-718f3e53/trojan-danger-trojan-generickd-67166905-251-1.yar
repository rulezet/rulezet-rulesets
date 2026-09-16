rule Trojan_Danger_Trojan_GenericKD_67166905_251_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_251_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48514fbe53798efc597a6b83399848824ab3b84f9958e372e1a3ff2badba50d9"

  strings:
    $s1 = "v Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}