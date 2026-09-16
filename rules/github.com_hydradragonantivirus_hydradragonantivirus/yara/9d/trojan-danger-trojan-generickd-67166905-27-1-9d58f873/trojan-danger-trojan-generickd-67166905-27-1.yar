rule Trojan_Danger_Trojan_GenericKD_67166905_27_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_27_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d26467de018fef5d1b4405c005f211eea76b8ab44a95ca0ab9bd822d76b78c30"

  strings:
    $s1 = "{Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}