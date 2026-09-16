rule Virus_Hijack_Trojan_GenericKDZ_105924_220_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_220_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4aa60752a1cc2594c94690226713a702111711745623985a8f72fc3637162eae"

  strings:
    $s1 = "Could not open file '%Fs': %s" fullword ascii
    $s2 = "Ken Reneris. List Ver 1.0." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}