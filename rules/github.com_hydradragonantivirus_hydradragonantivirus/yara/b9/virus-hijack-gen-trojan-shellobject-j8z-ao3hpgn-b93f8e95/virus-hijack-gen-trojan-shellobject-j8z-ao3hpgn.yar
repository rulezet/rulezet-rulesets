rule Virus_Hijack_Gen_Trojan_ShellObject_J8Z_aO3hPGn {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.J8Z@aO3hPGn.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcb691c00321cd69c5e5664d3416c1a0260d698ec1b551cd4bc323f4314b6394"

  strings:
    $s1 = "vqProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}