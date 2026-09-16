rule Virus_Hijack_Trojan_GenericKDZ_98113_117_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_117_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "141d549ae8a9776e54a1eef6b2c41371fbac8514fcaa4e48a89f98b3fee2e076"

  strings:
    $s1 = "%@hInd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}