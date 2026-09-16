rule Trojan_Autorun_Trojan_GenericKDZ_94847_307_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_307_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66ca10bacf01e827cb315c5fa42eadb64acfdef0ff8a1a4e6226b7f933ca8288"

  strings:
    $s1 = "2pIRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}