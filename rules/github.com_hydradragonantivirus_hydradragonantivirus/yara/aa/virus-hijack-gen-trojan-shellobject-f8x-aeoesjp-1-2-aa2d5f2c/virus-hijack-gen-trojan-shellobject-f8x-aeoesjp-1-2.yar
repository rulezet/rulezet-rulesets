rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aeOesjp_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aeOesjp_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5f2431c2e4b8d77ff596a8411407f18a92f4cac03cefd8514bd61e3ce7f8949"

  strings:
    $s1 = " <rdf:Description about='uuid:6d39c6d2-21ce-11d7-9cf3-c01b0f5ad522'" fullword ascii
    $s2 = "  <xapMM:DocumentID>adobe:docid:photoshop:6d39c6c9-21ce-11d7-9cf3-c01b0f5ad522</xapMM:DocumentID>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}