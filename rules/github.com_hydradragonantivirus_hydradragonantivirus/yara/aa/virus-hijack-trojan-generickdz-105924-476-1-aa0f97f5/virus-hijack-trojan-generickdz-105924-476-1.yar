rule Virus_Hijack_Trojan_GenericKDZ_105924_476_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_476_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0d967d5e76268d0f40eec692f2ff39f3d8026e8a87e0c33cef5d90609bc1352"

  strings:
    $s1 = "rebeC#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}