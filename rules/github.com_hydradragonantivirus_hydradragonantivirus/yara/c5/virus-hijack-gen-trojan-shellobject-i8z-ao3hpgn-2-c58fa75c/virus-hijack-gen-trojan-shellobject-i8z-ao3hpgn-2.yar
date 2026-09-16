rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aO3hPGn_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aO3hPGn_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5522c4a1da3f02b6b762435af24d51d2a3c338ffc6ea51cca2a1df99bf44e72a"

  strings:
    $s1 = "6Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}