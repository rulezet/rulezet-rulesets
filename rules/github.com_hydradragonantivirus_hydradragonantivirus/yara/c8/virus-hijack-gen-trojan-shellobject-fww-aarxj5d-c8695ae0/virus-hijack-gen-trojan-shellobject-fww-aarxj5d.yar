rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_aarXj5d {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbfff8366ec99544e1cd68b164fd1fcc4d09b3e2215ed72c868ffd3f38b48f3d"

  strings:
    $s1 = "hpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}