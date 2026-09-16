rule Virus_Hijack_Trojan_GenericKDZ_105924_308_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_308_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69233abbb01b5a58dbf3453301e850f3f1f8da5101642f7164cebaaa679cb18f"

  strings:
    $s1 = "S%ecHo" fullword ascii
    $s2 = "#D<VOlT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}