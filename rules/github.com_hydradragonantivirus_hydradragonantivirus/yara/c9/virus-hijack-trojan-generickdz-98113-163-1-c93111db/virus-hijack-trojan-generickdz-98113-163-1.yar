rule Virus_Hijack_Trojan_GenericKDZ_98113_163_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_163_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "003d9676336f1128c3e8e455b70c5a0b3338faac34c67c8fa82bbc146b316388"

  strings:
    $s1 = "y`NOMa" fullword ascii
    $s2 = "LURal(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}