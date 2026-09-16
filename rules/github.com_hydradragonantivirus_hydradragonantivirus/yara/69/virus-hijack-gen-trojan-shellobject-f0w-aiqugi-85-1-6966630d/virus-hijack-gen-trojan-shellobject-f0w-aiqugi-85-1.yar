rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_85_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_85_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f583cf6d73bfbb2e9c14aa2af8f68efcd4baf90fcb03d3ffd81cde85839bc52"

  strings:
    $s1 = "$Microsoft Root Certificate Authori" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}