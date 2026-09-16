rule Virus_Hijack_Trojan_GenericKDZ_103285_189 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_189.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbe3f8b208b4640313edfba714b1697941e5d99c2eb1cddf85f451d9e186cf5e"

  strings:
    $s1 = "ujOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}