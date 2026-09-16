rule Trojan_Danger_Gen_Variant_Ransom_XiaoBa_12 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.XiaoBa.12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f21f4139531fa05e29b5a2639cda894630bb0262c3c74283c94a5034063cca"

  strings:
    $s1 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)" fullword ascii
    $s2 = "BOGY'S GAME ENGINE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}