rule Virus_Hijack_Gen_Trojan_ShellObject_5yZ_aCEmdoo_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.5yZ@aCEmdoo_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "084116ad4afcabfb218eb36233f84eeb529e61280af12c6a0a693d4439348ebc"

  strings:
    $s1 = "soft Windows8h" fullword ascii
    $s2 = "gram F" fullword ascii
    $s3 = "$Time " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}