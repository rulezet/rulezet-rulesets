rule Trojan_Danger_Trojan_GenericKD_67166905_419_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_419_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbce676e047df0a9ceed3aecafc79903197b1b601a4896101b44613a96d81839"

  strings:
    $s1 = "opolicy, which might require you to return the software with the entire computer on which the software is" fullword ascii
    $s2 = "/&FouR#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}