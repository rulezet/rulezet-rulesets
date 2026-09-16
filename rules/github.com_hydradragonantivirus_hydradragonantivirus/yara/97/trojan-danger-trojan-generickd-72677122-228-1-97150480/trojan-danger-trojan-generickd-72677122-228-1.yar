rule Trojan_Danger_Trojan_GenericKD_72677122_228_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_228_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fe4327cc1052d0d1be936665d825b72cbab00b266eb01d37a116983dc937ef2"

  strings:
    $s1 = "HKCU\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page" fullword wide
    $s2 = "echo Y| cacls " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}