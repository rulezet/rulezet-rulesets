import "pe"
rule _Virus_Autorun_Gen_Variant_Application_Barys_1471_Virus_Autorun__486 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Gen.Variant.Application.Barys.1471.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_1.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_14_2.vir, VirusShareTrojanVbCrypt250_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36bbc80169bd128d160fb3869dcf23891b69a7765d8abb171897c9dfd0d58e3a"
    hash2       = "0ea76f5343284061fe91a1363d0a2116b76db249e7de5cc17a6971f30f805011"
    hash3       = "c25118c87134ffa298b9ec21b6abbfb10ced5f41dee519e34b593db27e0ce502"
    hash4       = "4f08e3a69121dfc3731f51c33e40cb14ff28c745c3471bd8ec1328cb7426f648"
    hash5       = "81f62aa60559e7596bfb8a5ff524e78623fa29e89f07b3f8e9b683132dc9ffb0"

  strings:
    $s1 = "CardStack::GetCardLocation() - Couldn't find the card." fullword wide
    $s2 = "Invalid CurrentDeck in game state data" fullword wide
    $s3 = "Invalid CurrentBackground in game state data" fullword wide
    $s4 = "Unable to write random auto continue to the options node" fullword wide
    $s5 = "Unable to write show tips to the options node" fullword wide
    $s6 = "Unable to write CurrentDeck to the options node" fullword wide
    $s7 = "Unable to write CurrentBackground to the options node" fullword wide
    $s8 = "Unable to write disabled tip node" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "b941ddedcc51e5706d41335adb4e6b2a" and (all of them)
    ) or (all of them)
}