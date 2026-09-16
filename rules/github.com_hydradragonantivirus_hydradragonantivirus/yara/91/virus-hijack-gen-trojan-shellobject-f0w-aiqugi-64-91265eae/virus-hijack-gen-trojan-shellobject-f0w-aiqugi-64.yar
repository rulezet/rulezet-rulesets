rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_64 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_64.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee48b15f837963af825258418d2ee72346f56c26c31bd645932d504b52059b10"

  strings:
    $s1 = "PY4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}