rule sig_20161208_0a9a9a7165ad84f456f7fc03f1da3e72 {
  meta:
    description = "datamaliciousorder - file 20161208_0a9a9a7165ad84f456f7fc03f1da3e72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e277e95d0bb57c2ec691f130bc4f2324c2234fabd592600d7ed7c1d692fe66de"

  strings:
    $s1 = "ew Date();vCf4[\"setUTC\"+\"FullYear\"](\"2003\");if (vCf4.getUTCFullYear().toString(10) == \"2003\") {var vYDw3 = vEt2.split(\"" ascii
    $s2 = "var vVr5 = new Function(\"vEt2\", '{return vEt2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIx8 = new Function(\"vEt2\"" ascii
    $s3 = "var vVr5 = new Function(\"vEt2\", '{return vEt2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIx8 = new Function(\"vEt2\"" ascii
    $s4 = "eturn vYDw3.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}