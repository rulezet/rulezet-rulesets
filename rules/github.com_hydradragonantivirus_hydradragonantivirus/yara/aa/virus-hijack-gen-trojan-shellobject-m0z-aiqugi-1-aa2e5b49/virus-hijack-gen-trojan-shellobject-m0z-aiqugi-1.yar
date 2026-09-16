rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae401f2515662c0ffe7df31c70e4c449981a051ebda9ad333d01b08399adeff2"

  strings:
    $s1 = "nG4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}