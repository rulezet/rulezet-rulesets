rule Trojan_Autorun_Trojan_GenericKDZ_95048_16 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.95048_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cec52620d9f4385eae424510104f5bfb4f8acff60866b7043afe82c45b923180"

  strings:
    $s1 = "b9e985j?jAmA@=rGrIuIHEzOzQ}QPM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}