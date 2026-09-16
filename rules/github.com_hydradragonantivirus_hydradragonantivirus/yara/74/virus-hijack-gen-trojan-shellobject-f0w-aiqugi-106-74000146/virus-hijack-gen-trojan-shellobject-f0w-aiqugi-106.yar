rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_106 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_106.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37d740e0f15dfbaa35e4899e3c5ef272334b29a313c54f71763c4603b2812a22"

  strings:
    $s1 = "#4. Language Packs and Proofing Tools. If you acq" fullword ascii
    $s2 = "bAtS)At" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}