rule sig_20161207_347227d1fac100c692f489d91ec83624 {
  meta:
    description = "datamaliciousorder - file 20161207_347227d1fac100c692f489d91ec83624.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "514aad2cbcab30082179a911ba40f72d394726be9fe6bc2b7e10932d577dbd39"

  strings:
    $s1 = "new Date();vRs9[\"setUTCFullYear\"](\"2003\");if (vRs9.getUTCFullYear().toString(10) == \"2003\") {var vVEu6 = vZp4.split(\"####" ascii
    $s2 = "var vMDm2 = new Function(\"vZp4\", '{return vZp4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBc6 = new Function(\"vZp4" ascii
    $s3 = "var vMDm2 = new Function(\"vZp4\", '{return vZp4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBc6 = new Function(\"vZp4" ascii
    $s4 = "urn vVEu6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}