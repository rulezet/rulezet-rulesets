rule Virus_Danger_Trojan_GenericKDZ_103285_32 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103285_32.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6714d8dff55ea2e2def2364d5099eedb9275ed75988e54422ca552344e38235b"

  strings:
    $s1 = "features or not use them. For more informa tion about these features, see the Offi`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}