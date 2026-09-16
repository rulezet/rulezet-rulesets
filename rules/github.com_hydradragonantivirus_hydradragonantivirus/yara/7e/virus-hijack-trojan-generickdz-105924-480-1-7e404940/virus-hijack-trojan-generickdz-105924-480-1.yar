rule Virus_Hijack_Trojan_GenericKDZ_105924_480_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_480_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb5e79b2d66be4a1d06e59e142fde54621f96065481090b8956161c049504c4e"

  strings:
    $s1 = "\"%PAta*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}