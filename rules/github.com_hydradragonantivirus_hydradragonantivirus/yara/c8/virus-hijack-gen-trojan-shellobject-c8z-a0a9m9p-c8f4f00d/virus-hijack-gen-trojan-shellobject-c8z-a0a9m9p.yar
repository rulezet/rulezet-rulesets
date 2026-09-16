rule Virus_Hijack_Gen_Trojan_ShellObject_C8Z_a0a9m9p {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8Z@a0a9m9p.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7696534159dc434d30bef3e5832d06000f6cd2037732ef481013cc225d91a42d"

  strings:
    $s1 = "C\"Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}