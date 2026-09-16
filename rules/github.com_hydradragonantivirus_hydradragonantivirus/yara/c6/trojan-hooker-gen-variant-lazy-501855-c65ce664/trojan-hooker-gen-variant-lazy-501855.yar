rule Trojan_Hooker_Gen_Variant_Lazy_501855 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Gen.Variant.Lazy.501855.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "468c9f6bd8d2c63e453e96f1739188066d8334bc2545e889f6d74d63f9494e9f"

  strings:
    $s1 = "Dive tastai cp esca" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}