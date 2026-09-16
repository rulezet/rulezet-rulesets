rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_23 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "523aae84af185cd8acd91f9c227d6608c8c00b819f1f7807099b49c94fa80e51"

  strings:
    $s1 = "-X4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}