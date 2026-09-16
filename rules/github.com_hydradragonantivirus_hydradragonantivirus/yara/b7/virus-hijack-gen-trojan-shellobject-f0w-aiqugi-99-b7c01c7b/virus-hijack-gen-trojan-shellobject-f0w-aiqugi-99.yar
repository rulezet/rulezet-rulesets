rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_99 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_99.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0945cbaaaa7f4ca36fcc0c75348f961a43225914d06986b39758c0208ccdb15"

  strings:
    $s1 = "?4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}