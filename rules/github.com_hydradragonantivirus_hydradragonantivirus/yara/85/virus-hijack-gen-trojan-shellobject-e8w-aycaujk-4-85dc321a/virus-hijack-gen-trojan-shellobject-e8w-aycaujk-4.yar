rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86f906809ec5f21a896c8736d5414e578bbecdb7c79835262fbe63281620e570"

  strings:
    $s1 = "program and/or materials resulting from services (or direct product thereof) will be exported,`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}