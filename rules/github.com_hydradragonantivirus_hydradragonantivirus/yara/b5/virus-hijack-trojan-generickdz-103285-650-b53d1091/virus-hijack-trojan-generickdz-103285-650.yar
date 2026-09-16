rule Virus_Hijack_Trojan_GenericKDZ_103285_650 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_650.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f01284c377c174184a34d4fb186e2deadc5c4dbc2bc8bcffc29ff6021e2fbced"

  strings:
    $s1 = "glom[n`" fullword ascii
    $s2 = "kfSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}