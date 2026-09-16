rule Virus_Hijack_Trojan_GenericKDZ_105924_163_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_163_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6ccb48642af293fff9992697e1e602d683359597f0a42ba0e634f797838ff50"

  strings:
    $s1 = "P_controlfp_s(((void *)0), 0x00010000, 0x00030000)" fullword wide
    $s2 = "vq`Dewy" fullword ascii
    $s3 = "MInd}o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}