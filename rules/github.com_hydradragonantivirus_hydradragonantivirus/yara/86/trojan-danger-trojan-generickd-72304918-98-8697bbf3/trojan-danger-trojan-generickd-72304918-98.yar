rule Trojan_Danger_Trojan_GenericKD_72304918_98 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_98.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18de87f5d904ac3e5214d221536622d97923d847f23639bc8e9366cbd2fa2b51"

  strings:
    $s1 = "V[TRap?<RRRRRRRRRRna" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}