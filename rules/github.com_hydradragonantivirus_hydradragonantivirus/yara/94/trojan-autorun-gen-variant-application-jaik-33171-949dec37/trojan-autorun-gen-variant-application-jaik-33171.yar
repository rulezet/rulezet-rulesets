rule Trojan_Autorun_Gen_Variant_Application_Jaik_33171 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Application.Jaik.33171.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e73d2a8dd6dad3b18734779e06e36193279465616866091abb5d26fb5a93fbe5"

  strings:
    $s1 = "<embed autoplay=\"true\" src=\"sound.mp3\"  width=\"1\" height=\"1\" />" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}