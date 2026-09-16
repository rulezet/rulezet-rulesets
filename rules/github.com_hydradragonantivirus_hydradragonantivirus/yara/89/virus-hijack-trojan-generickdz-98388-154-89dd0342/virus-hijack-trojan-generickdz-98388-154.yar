rule Virus_Hijack_Trojan_GenericKDZ_98388_154 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_154.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d26f167b785d2f0ff36175c5b45e69b4b7f101f654d64da51e5ae370ba2065f5"

  strings:
    $s1 = "program and/or materials resulting from services (or direct product thereof) will be exported,`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}