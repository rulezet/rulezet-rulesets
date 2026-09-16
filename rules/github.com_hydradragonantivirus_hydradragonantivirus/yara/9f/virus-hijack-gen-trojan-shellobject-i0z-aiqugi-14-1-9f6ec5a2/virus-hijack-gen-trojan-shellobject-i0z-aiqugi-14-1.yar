rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8a75e69d2eadaed32e7da732fd1f41fbeb5d976d6e696f46d1cbec65071ae94"

  strings:
    $s1 = "bLInno Setup Setup Data (5.5.0) (u)" fullword ascii
    $s2 = "B@SIll" fullword ascii
    $s3 = "k}{lUsH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}