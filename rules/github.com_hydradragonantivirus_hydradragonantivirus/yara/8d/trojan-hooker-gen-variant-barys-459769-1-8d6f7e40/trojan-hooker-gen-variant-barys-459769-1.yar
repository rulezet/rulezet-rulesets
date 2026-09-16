rule Trojan_Hooker_Gen_Variant_Barys_459769_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Gen.Variant.Barys.459769_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5154171754884ad31df735ffbf12d16fa2bc9f3781e557d322aad223f4ceb86f"

  strings:
    $s1 = "SECURE APPLICATION DEVELOPMENT1)0'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}