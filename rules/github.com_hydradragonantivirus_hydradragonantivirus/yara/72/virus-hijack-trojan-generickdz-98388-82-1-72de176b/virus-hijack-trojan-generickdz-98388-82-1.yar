rule Virus_Hijack_Trojan_GenericKDZ_98388_82_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_82_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "189eff033ddf44e8bc0ceb85a98de532e94477de024ea49c1c5966ee1f41128f"

  strings:
    $s1 = "Jaun$z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}