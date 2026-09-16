rule Virus_Hijack_Trojan_Agent_DQQO_53_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_53_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6379fe9cdb770360ce8f2ba051ba209ebae5154cfecae09ea2ea71e825bcfdc7"

  strings:
    $s1 = " xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:RDF xmlns:rdf=\"htt" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}