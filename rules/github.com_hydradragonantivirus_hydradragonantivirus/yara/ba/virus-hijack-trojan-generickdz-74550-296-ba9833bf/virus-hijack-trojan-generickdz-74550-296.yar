rule Virus_Hijack_Trojan_GenericKDZ_74550_296 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_296.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55f19601b0876be4b1fe9db1821ec30f9fc8531712097fa80e23d3e8d7e941f4"

  strings:
    $s1 = "pEAI(2Z!" fullword ascii
    $s2 = "hEAT@J" fullword ascii
    $s3 = "Tx@!hEAT@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}