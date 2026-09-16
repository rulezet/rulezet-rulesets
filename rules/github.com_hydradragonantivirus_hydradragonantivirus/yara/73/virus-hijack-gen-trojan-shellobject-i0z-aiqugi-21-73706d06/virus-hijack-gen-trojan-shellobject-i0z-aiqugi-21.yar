rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_21 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_21.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b39a7a2ae1ce37d208a7b33a822ece69f11500924ce86d9f8622157700863a6e"

  strings:
    $s1 = "vG4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}