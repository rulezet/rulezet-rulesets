rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12c2d8753aa0b89e8fa546117f17850c52f056e85331d6e118fb0e16523222ac"

  strings:
    $s1 = "Null}@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}