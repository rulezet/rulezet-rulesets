rule Trojan_Danger_Trojan_GenericKD_72304918_146 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_146.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf95425b55d922e128c437a5cd14c6c79d6ef79c49f2c832d489a306ba98c4fd"

  strings:
    $s1 = "V[TRap?<RRnu" fullword ascii
    $s2 = "V[TRap?<nau" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}