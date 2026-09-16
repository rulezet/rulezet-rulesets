rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_85_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_85_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "960c3733e488b34a74f364cdd2e739d0f26121f7c68b67b504ce4e0d8ee92e6c"

  strings:
    $s1 = "XK4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}