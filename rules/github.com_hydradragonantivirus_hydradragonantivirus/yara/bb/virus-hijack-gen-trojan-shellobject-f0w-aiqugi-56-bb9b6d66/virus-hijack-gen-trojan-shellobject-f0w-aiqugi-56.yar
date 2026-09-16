rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_56 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_56.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b851bc73521246d129ab9f2cb0c62fa0cbf5012275fde2651d2b18fa76907d60"

  strings:
    $s1 = ",\\4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}