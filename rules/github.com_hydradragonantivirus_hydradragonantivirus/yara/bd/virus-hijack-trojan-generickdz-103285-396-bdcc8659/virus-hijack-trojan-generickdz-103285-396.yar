rule Virus_Hijack_Trojan_GenericKDZ_103285_396 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_396.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1eeeab964cbc8a57b89d7f0c2753cdd299dac00650183aad0df1c41875babd7"

  strings:
    $s1 = "features or not use them. For more informa tion about these features, see the Offi`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}