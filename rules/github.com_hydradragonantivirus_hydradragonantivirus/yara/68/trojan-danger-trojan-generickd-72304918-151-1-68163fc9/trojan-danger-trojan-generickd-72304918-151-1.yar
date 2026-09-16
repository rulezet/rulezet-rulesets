rule Trojan_Danger_Trojan_GenericKD_72304918_151_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_151_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d595c33d0c8aa45f70023384c50e0085d24538369e4f0212c07a4d33c01317fd"

  strings:
    $s1 = "\\University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}