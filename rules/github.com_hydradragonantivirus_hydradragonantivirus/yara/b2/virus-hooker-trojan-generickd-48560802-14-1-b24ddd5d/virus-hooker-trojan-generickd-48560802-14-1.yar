rule Virus_Hooker_Trojan_GenericKD_48560802_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.GenericKD.48560802_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5645d13b3a74b69b2152235a89d15ca5caad4a3398a15c56231c94fdc778d32"

  strings:
    $s1 = ")>LaSs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}