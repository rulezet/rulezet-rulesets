rule sig_20160525_abe7c64b144b4f1dcca82d2e11e84db0 {
  meta:
    description = "datamaliciousorder - file 20160525_abe7c64b144b4f1dcca82d2e11e84db0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c4fe855b2010601e2e44a676390fce35dd75c3c49476dcd4c5202a7b18de00e"

  strings:
    $s1 = "oitcnuf\\n;\"e6x\\\\uR\" = deerdp rav\\n;\"peel35x\\\\\" = sdnetp rav\\n;\"ec6x\\\\\" = tsilslianbmuhtop rav\\n;\"t76x\\\\n\" = " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}