rule Virus_Hijack_Trojan_GenericKDZ_105924_363_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_363_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "faf4778d6069e159023e48bdf59f3a940a12b7d6b59a19f4c47e201ddd168c96"

  strings:
    $s1 = "w#auRa" fullword ascii
    $s2 = "/ ToLd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}