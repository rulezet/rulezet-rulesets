rule Trojan_Danger_Generic_Dacic_1A7FA519_A_9A655406_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.9A655406_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6ac2a48421d75a148e4b6f6954f0e3a0c9669aa8c65a835a56255cda02e7d4f"

  strings:
    $s1 = "ROracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}