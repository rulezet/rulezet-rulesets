rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_24 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_24.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3e2ca79248d589af527909b3501513bd2cc104bc72506f49f66f9e547a48044"

  strings:
    $s1 = "~&KeUp" fullword ascii
    $s2 = "[&FRom" fullword ascii
    $s3 = "GaDe#K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}