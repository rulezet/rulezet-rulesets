rule Trojan_Autorun_Trojan_GenericKDZ_94847_119_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_119_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c204e2be31b418327d0e6994863139e539da55f0bbee870af945d297f0fba6d1"

  strings:
    $s1 = "`Ewhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}