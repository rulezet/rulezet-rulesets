rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ef4087e1d861d938bfece79099fcb9d603cc350c39a2968dd14ee93bfe6cd64"

  strings:
    $s1 = "<Module>{46EADFD1-6C46-4AC8-A70E-96281A88E536}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}