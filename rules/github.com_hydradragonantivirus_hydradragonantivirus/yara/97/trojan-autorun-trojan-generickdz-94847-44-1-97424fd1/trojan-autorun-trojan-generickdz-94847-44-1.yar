rule Trojan_Autorun_Trojan_GenericKDZ_94847_44_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_44_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e5447f7dc2cb0a5a1faf436734fb10e560ebbf05e4145fa332505b58fd0a8e8"

  strings:
    $s1 = ".automatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}