rule Virus_Hijack_Trojan_GenericKDZ_103285_358 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_358.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49df6246ea1be069e5422cdbdbcfb51aed7fa74a196b98478da716ca5a1d42ab"

  strings:
    $s1 = "OOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}