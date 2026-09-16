rule Virus_Hijack_Gen_Trojan_ShellObject_r0Z_aKzulAn_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r0Z@aKzulAn_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34247a9675530466bc37496783624f7a413e073e64402bdf1f3ebed9c56ce2e9"

  strings:
    $s1 = "P?taUn" fullword ascii
    $s2 = "fuss>z" fullword ascii
    $s3 = "$bReAk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}