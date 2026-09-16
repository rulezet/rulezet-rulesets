rule Trojan_Danger_Trojan_GenericKD_72677122_7 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abf22a46d134efd78f9aefe1bae2151162fb5bf7e1c0ea7cedb81f79e8999eed"

  strings:
    $s1 = "Ruby 3.2.2 API Reference.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}