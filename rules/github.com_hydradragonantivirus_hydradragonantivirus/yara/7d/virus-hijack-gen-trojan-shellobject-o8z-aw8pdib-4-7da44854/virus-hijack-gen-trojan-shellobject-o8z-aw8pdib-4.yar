rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_aW8PDib_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@aW8PDib_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e478db061abb158461b841e623835ddcba8e3f9d5c011c6406ca57b7212fd46b"

  strings:
    $s1 = "features or not use them. For more informa tion about these features, see the Offi`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}