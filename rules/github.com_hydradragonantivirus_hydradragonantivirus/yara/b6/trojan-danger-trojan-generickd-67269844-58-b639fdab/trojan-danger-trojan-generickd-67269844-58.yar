rule Trojan_Danger_Trojan_GenericKD_67269844_58 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67269844_58.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b686be5a8bcb63a8c5ee4872965dc9f39498b503642b8771bdda9ed97173e7f"

  strings:
    $s1 = "GWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}