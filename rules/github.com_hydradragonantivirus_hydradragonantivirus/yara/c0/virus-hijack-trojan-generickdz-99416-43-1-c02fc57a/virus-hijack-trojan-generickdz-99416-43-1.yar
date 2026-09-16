rule Virus_Hijack_Trojan_GenericKDZ_99416_43_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_43_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "541e54c5aee391250f63ebb5c39d97d84890c3c7afee82ddd55a3648bba3b6ff"

  strings:
    $s1 = "&sALE>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}