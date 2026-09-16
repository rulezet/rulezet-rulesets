rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aSl2g6j_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aSl2g6j_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b98b4a58ffc62e2300baa88e627c709a0b8a2eaecfecabe9f93a6b3db4902b23"

  strings:
    $s1 = "Getting Windows build from registry" fullword wide
    $s2 = "Determining Windows version" fullword wide
    $s3 = "Trying to load SPP based on Windows version" fullword wide
    $s4 = "Spp loading result" fullword wide
    $s5 = "Cobalt client library" fullword wide
    $s6 = "Used for the Inline Translation experiences" fullword wide
    $s7 = "@{saMP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}