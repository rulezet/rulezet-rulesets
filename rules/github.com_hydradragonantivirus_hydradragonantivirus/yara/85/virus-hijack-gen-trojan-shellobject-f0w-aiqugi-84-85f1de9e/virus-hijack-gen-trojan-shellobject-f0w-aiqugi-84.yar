rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_84 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_84.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c02097dba1a753a064d79df6b2f2b0fdd7dd7fa68aaf11469c8a116f97070db8"

  strings:
    $s1 = "!4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}