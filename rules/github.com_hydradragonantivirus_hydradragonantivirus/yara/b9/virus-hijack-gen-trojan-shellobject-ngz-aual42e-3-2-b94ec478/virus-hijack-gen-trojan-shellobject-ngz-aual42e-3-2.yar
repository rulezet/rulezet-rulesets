rule Virus_Hijack_Gen_Trojan_ShellObject_nGZ_auAl42e_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.nGZ@auAl42e_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ca40fa8fa8ec5af8f19966989326953a82762005a8a20b332df01e8718afee7"

  strings:
    $s1 = "MaRL@L<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}