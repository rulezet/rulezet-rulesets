rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_60 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_60.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3306ee38b3f38822126cb1e38bb8611b03056d344b182692bef951831edebc2d"

  strings:
    $s1 = "C4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}