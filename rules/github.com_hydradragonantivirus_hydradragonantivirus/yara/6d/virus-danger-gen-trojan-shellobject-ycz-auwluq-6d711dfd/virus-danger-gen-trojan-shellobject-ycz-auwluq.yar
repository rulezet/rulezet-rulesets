rule Virus_Danger_Gen_Trojan_ShellObject_YCZ_auWluQ {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.YCZ@auWluQ.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f26ab5931864e554b6a79829b26826032c03616af5e761a0690a72a39aa9679"

  strings:
    $s1 = "that you may receive from Microsoft during that year are also covered, but only for`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}