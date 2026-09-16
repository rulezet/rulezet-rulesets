rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_auLSMIo_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@auLSMIo_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "486bace70fc33408f1f8504e52c01806229a765a5341546292d0d744e2534844"

  strings:
    $s1 = "!This is a PE executable" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}