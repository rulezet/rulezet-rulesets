rule Virus_Hijack_Trojan_GenericKDZ_98113_205_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_205_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b04633d334825500349ed9efa0dae925890f370fe5f3f970ab3626ae68f6d24f"

  strings:
    $s1 = "TOSH{o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}