rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_ayWIjmh_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@ayWIjmh_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67f796b77639a67a04bbb94524342c3e3f3efe99bb4a494def892fd118a58991"

  strings:
    $s1 = " <rdf:Description about='uuid:999b8ee7-21cf-11d7-9cf3-c01b0f5ad522'" fullword ascii
    $s2 = "  <xapMM:DocumentID>adobe:docid:photoshop:999b8ee1-21cf-11d7-9cf3-c01b0f5ad522</xapMM:DocumentID>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}