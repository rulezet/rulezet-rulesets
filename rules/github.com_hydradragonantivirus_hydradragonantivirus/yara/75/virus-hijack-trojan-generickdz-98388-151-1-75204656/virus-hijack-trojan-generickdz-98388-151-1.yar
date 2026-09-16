rule Virus_Hijack_Trojan_GenericKDZ_98388_151_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_151_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "faf2fc0132329f9bf9ddc10cc757f0d439c32e4043b9737c021b0fbbecff7cec"

  strings:
    $s1 = "FoiL<U" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}