rule Virus_Hijack_Trojan_GenericKDZ_105924_564_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_564_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45c88190411bcf9d40d2f65362900d8730e93c803ce8077339b594935e5cfe6f"

  strings:
    $s1 = "NauT$b" fullword ascii
    $s2 = "z_C(eLMy" fullword ascii
    $s3 = "hewt$&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}