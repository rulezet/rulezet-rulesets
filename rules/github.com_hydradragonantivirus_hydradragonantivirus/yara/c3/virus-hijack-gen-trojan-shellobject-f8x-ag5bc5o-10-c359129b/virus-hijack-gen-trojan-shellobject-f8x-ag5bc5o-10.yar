rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "303e841c51e13ee90736f795b1de57c2cfd9ffbf8615c8ea3926cb22a672f27b"

  strings:
    $s1 = "Ghundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}