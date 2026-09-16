rule Virus_Hijack_Gen_Trojan_ShellObject_p4Z_aG4Sr2m_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p4Z@aG4Sr2m_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3713347b82a63cd02707e10dc8c7bf5a0636baf7af3112127d403eac77e360e1"

  strings:
    $s1 = "Fthat party must agree that this agreement applies to the transfer and use of the software. You may not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}