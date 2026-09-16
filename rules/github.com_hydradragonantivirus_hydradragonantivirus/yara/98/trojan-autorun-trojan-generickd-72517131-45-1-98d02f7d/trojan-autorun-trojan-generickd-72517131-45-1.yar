rule Trojan_Autorun_Trojan_GenericKD_72517131_45_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_45_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "229ddf25ff64c377f9c9d2a69fe1944e5e345f018866fafa69f113deedb43daf"

  strings:
    $s1 = "kD4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}