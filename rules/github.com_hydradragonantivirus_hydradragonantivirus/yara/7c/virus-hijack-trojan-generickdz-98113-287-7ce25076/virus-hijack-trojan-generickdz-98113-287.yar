rule Virus_Hijack_Trojan_GenericKDZ_98113_287 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_287.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c39b553f7c0b5cf1b156e2fa76bba8b96ed6eeebb1ee160c2fcde5fdb5b2c1a8"

  strings:
    $s1 = "Rh2cw>o[>!ADet" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}