rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_107 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_107.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec96ce82a397c4bd1914d0d2af44dc9ab803d272aa7af48840d57e10797f6cb7"

  strings:
    $s1 = "<4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}