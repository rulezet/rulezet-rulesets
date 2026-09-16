rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_aarXj5d_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b7b1827ff179dec719958bd11a67955bde4bb25e3d050af0667f40079c47d61"

  strings:
    $s1 = "0purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii
    $s2 = ";PeNSy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}