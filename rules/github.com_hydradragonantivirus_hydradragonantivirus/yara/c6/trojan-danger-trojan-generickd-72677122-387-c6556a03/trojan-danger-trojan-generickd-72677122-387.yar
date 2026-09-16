rule Trojan_Danger_Trojan_GenericKD_72677122_387 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_387.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62fffddd5d976bae282361aa318abf054c2e81d9ceb7506d44ea82f724f58d13"

  strings:
    $s1 = "{Module Docs.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}