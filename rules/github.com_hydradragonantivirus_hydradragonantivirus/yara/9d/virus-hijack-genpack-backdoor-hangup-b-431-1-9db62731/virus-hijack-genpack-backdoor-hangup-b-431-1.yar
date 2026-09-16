rule Virus_Hijack_GenPack_Backdoor_Hangup_B_431_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_431_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "287fddb223dbfce4be3c0db2760bc07a4c16400f9e03816bb99fcac9da803f34"

  strings:
    $s1 = " xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:RDF xmlns:rdf=\"htt" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}