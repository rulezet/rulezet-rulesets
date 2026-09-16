rule Virus_Hijack_Trojan_GenericKDZ_98388_229 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_229.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2827168516594e7c68fe0b4ff01f041c6b57eeaaff4dbb3e0a707dfbb2601840"

  strings:
    $s1 = "MetaLink has information on which products have been translated for the supported languages (http://metalink.oracle.c`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}