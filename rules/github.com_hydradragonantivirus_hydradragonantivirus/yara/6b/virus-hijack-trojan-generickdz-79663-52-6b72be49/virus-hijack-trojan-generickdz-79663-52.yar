rule Virus_Hijack_Trojan_GenericKDZ_79663_52 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_52.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d89498d4adf426a974d10094d0a7600b44f17fbb11231419ded2c5fe1b2eddfc"

  strings:
    $s1 = "%{this notice will include a copy of your agreemen" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}