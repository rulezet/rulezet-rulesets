rule Trojan_Danger_Trojan_GenericKD_72304918_68_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_68_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddf308d7f1ba2dae0f0b918459cd1728aeda8b1a590ce1e160e731cba0574fc9"

  strings:
    $s1 = "LIFT[PZ]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}