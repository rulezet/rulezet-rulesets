rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_au0WBJh {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@au0WBJh.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55743a830175d5985ddaffae56a1bbb9985b977081ef51430062a0d777659d32"

  strings:
    $s1 = "(orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}