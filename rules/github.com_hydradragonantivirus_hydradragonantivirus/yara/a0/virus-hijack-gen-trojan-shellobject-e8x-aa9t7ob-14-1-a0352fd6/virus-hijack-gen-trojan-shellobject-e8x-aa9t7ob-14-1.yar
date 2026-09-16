rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "621f8b48e6cd5586e3dfb5f83a24998de6903a73e6c818ad663b036f0de93250"

  strings:
    $s1 = "<Module>{DA647478-C5A6-490D-B974-3A440890D69E}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}