rule Virus_Hijack_Gen_Trojan_ShellObject_eCX_aijlKSl_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eCX@aijlKSl_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d185625884b2d58deb9d6c6e1eee85a38620ac7da70649b57727a8b77001e6ef"

  strings:
    $s1 = "8#sEME" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}