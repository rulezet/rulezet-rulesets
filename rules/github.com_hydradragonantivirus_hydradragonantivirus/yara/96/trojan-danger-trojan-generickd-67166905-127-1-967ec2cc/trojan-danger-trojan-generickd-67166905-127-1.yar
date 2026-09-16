rule Trojan_Danger_Trojan_GenericKD_67166905_127_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_127_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "783264a7b92d655e6e369cbbb092858d7b4a665922bf6342b8dfdb7f57d1bc4b"

  strings:
    $s1 = "^University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}