rule Virus_Hijack_Trojan_GenericKDZ_98113_96 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_96.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc5dd7c526ee924d70da8debc4eccd06eb8a524d33be83ed22d20c42b950df73"

  strings:
    $s1 = "}NITo&vW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}