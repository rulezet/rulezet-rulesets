rule Virus_Hijack_Trojan_GenericKDZ_98113_236 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_236.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f88b77da0535a5c47cf3d2b41c6f4be48e999fb67a652308d2e94bbdda510e9"

  strings:
    $s1 = "<qby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}