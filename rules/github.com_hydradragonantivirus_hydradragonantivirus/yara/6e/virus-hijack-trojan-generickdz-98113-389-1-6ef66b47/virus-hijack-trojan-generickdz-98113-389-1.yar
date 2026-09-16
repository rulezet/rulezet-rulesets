rule Virus_Hijack_Trojan_GenericKDZ_98113_389_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_389_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "154e7fed4aa62b909b79be60e1dd681527446b2ee63a5058f68038cbba3d7ce3"

  strings:
    $s1 = "JiMp>os" fullword ascii
    $s2 = "e!}COTo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}