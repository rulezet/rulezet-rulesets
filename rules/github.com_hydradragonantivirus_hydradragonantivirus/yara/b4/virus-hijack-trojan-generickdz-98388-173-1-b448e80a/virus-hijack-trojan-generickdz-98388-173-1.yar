rule Virus_Hijack_Trojan_GenericKDZ_98388_173_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_173_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d367ac652dfe93cbb560ca6251c2cb63aaaa64d05efd5008c97e31116bc21aca"

  strings:
    $s1 = "j(puTT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}