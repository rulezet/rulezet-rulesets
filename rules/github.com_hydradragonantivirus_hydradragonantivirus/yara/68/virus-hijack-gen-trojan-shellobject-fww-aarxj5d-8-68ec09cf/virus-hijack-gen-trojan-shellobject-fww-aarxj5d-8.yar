rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_aarXj5d_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f40b74032c08aae407c1b3f5ba8041f32e6ee492640ea2bbe61abbbcf88465f"

  strings:
    $s1 = "2purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii
    $s2 = "Q)kaSA" fullword ascii
    $s3 = " T)kaSA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}