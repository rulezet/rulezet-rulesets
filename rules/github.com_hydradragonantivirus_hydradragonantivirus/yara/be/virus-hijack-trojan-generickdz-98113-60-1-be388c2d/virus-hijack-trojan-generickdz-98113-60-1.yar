rule Virus_Hijack_Trojan_GenericKDZ_98113_60_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_60_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51db038472ae04e1525e37fafcce8f62b1b9ddf801c9193b075a6abe9a934ab4"

  strings:
    $s1 = "p>wicK" fullword ascii
    $s2 = "kayo%J" fullword ascii
    $s3 = "+W)Q`k%`!StuE" fullword ascii
    $s4 = "Ak^`sHoo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}