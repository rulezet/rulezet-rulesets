rule Trojan_Autorun_Trojan_GenericKDZ_94847_331_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_331_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07c13f88bf3d35a4ccc199aeb8b1a8d38a29941a51526fbe8b09063bf6136078"

  strings:
    $s1 = "Nautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}