rule Virus_Hijack_Gen_Trojan_ShellObject_j4Z_aqH1LVc_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j4Z@aqH1LVc_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49351daf520ea1dee315e7ae4c91e3a273999eeb963513cdf3abbc4fac38b8ac"

  strings:
    $x1 = "c:\\Documents and Settings\\William Fread\\My Documents\\Visual Studio Projects\\bundles\\bundles\\Release\\bundle.pdb" fullword ascii
    $s2 = "v\"sion" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}