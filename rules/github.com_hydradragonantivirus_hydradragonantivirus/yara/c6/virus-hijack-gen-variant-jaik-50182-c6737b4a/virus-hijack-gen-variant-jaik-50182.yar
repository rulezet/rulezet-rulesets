rule Virus_Hijack_Gen_Variant_Jaik_50182 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Jaik.50182.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2db2b783bde02b9f4f89b101d2b045eac713773dd96aeb9f65c4ada152a72abb"

  strings:
    $s1 = "kernel)V6" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}