rule Trojan_Autorun_Trojan_GenericKDZ_94847_369_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_369_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbad61f5ed55f687c1a492372c62df4f7f591f1ad6523a47663d60160621fc8a"

  strings:
    $s1 = "':IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}