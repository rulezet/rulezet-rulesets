rule Trojan_Autorun_Trojan_GenericKD_73131881 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.73131881.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d030ceb249184651162619f0b4a28e94b1a2cc6aaa8a05478ce28ab62bf9fda"

  strings:
    $s1 = "Pobs'I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}