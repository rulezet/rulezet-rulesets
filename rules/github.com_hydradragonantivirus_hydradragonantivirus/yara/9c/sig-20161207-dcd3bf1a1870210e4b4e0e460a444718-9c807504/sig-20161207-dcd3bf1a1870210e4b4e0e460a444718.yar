rule sig_20161207_dcd3bf1a1870210e4b4e0e460a444718 {
  meta:
    description = "datamaliciousorder - file 20161207_dcd3bf1a1870210e4b4e0e460a444718.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "453e54a37bbb0b7ece8d4f83b5c65dccfcaf61c630346418228d543b08ffeebb"

  strings:
    $s1 = "= new Date();vIe2[\"setUTCFullYear\"](\"2003\");if (vIe2.getUTCFullYear().toString(10) == \"2003\") {var vGCf1 = vDDe6.split(\"#" ascii
    $s2 = "var vTr3 = new Function(\"vDDe6\", '{return vDDe6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQl1 = new Function(\"vDDe" ascii
    $s3 = "var vTr3 = new Function(\"vDDe6\", '{return vDDe6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQl1 = new Function(\"vDDe" ascii
    $s4 = "return vGCf1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}