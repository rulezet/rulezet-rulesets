rule sig_20161208_b8c644a6f0318e724bb9f53fadc880a5 {
  meta:
    description = "datamaliciousorder - file 20161208_b8c644a6f0318e724bb9f53fadc880a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec9488491bdf07cdad958061e6b38b71cb397ba7557b60c2ac5f3b7fba9af9d3"

  strings:
    $s1 = "var vYm2 = new Function(\"vNe2\", '{return vNe2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXAm8 = new Function(\"vNe2" ascii
    $s2 = " new Date();vHHt5[\"setUTC\"+\"FullYear\"](\"2003\");if (vHHt5.getUTCFullYear().toString(10) == \"2003\") {var vIAs0 = vNe2.spli" ascii
    $s3 = "); return vIAs0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vYm2 = new Function(\"vNe2\", '{return vNe2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXAm8 = new Function(\"vNe2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}