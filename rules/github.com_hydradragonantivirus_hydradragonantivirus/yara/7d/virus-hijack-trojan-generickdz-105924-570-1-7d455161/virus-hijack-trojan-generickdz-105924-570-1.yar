rule Virus_Hijack_Trojan_GenericKDZ_105924_570_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_570_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "136aae27db8ae6f838732b1da512a8e6da7c91719901f34766c6c75442150f36"

  strings:
    $s1 = "MITt;|n" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}