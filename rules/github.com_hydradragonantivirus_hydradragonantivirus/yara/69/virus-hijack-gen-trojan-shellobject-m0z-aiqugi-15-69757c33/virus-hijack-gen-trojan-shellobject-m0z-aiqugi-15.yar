rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6cae6e6d635835cf284eb5fac6ba59aa4756a6f4030c05fa6c9940da4bcb2ed"

  strings:
    $s1 = "04. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}