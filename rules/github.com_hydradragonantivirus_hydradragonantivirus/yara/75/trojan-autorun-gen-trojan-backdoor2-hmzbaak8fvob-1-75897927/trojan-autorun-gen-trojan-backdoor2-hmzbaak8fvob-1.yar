rule Trojan_Autorun_Gen_Trojan_Backdoor2_HmZbaaK8fvob_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.HmZbaaK8fvob_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bddb51f4cafea6f9b2229a9afda9053bed9b18e937a10097e22acd074e02d574"

  strings:
    $s1 = "c4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}