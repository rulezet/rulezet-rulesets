rule Trojan_Danger_Trojan_GenericKDZ_72354 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKDZ.72354.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67c8b857b249444d0b84fcecfc61d4f5d8c5b761170d88ebe918e111389808b9"

  strings:
    $s1 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)" fullword ascii
    $s2 = "BOGY'S GAME ENGINE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}