rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_a853Pwn_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@a853Pwn_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c7e20f85a69e842c843a6ea03ef33a0e9ad050460458eebbd5ecde25e44512a"

  strings:
    $s1 = "Content-Disposition: attachment; filename=PurpleMood.scr" fullword ascii
    $s2 = "RCPT TO: <test@pact518.hit.edu.cn>" fullword ascii
    $s3 = "Subject:hi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}