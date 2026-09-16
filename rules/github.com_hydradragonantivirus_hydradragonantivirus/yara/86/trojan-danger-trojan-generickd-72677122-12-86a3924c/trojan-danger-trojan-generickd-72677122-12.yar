rule Trojan_Danger_Trojan_GenericKD_72677122_12 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b79f9178bad91464fc1ba17a1db00543b5a84c6acf8c262b8edcbf5300c0c1bf"

  strings:
    $s1 = "System Configuration.lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}