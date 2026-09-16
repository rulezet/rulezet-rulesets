rule Virus_Hijack_Trojan_GenericKDZ_98388_204_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_204_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f07769a1eb1b4fd79166471c67d5eb387c9fdeb0fc8451e5a09e49b3d24a5f5f"

  strings:
    $s1 = "D3SOp:DITe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}