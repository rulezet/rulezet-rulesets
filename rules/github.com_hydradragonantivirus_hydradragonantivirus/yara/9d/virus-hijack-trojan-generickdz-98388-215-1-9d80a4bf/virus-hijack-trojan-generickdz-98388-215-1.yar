rule Virus_Hijack_Trojan_GenericKDZ_98388_215_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_215_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c831e0d7149c722a61e0cc6faffa2bbd7bd623396aa7fa0038f32b00a407993"

  strings:
    $s1 = ">:JOCh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}