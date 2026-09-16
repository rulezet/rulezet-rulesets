rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_au0WBJh_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@au0WBJh_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05026d671739e0c3dc0309030ec8ae18a6a5454a2c631195161250b615457669"

  strings:
    $s1 = "vborders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}