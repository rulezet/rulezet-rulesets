rule Virus_Hijack_Trojan_GenericKDZ_105924_392_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_392_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c430e7779bb7681dc4a185daebeac119af9213dd255798bebef98a877dc452ca"

  strings:
    $s1 = "JAuK%o" fullword ascii
    $s2 = "[heAr>" fullword ascii
    $s3 = "aK)proa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}