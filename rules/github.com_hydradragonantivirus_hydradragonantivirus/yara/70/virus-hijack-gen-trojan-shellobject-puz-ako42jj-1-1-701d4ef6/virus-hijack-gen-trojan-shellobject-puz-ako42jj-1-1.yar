rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_aKo42Jj_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53c1485d7f59ca506e30ffad42721eb9f0b0ef6b15ea80aceaa58c0a6b9ce844"

  strings:
    $s1 = "0(cEll?$" fullword ascii
    $s2 = "B%icEd" fullword ascii
    $s3 = "k>gEaN&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}