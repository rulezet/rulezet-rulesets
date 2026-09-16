rule sig_20161207_c0dc44f729678738410175718d3857ee {
  meta:
    description = "datamaliciousorder - file 20161207_c0dc44f729678738410175718d3857ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "346e309aa6e5719c920272a9bd3c1d68874348bca200ce8d8e3f3b047fa3c82c"

  strings:
    $s1 = " = new Date();vCw0[\"setUTCFullYear\"](\"2003\");if (vCw0.getUTCFullYear().toString(10) == \"2003\") {var vFk9 = vMMw4.split(\"#" ascii
    $s2 = "var vGy5 = new Function(\"vMMw4\", '{return vMMw4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGDw3 = new Function(\"vMM" ascii
    $s3 = "var vGy5 = new Function(\"vMMw4\", '{return vMMw4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGDw3 = new Function(\"vMM" ascii
    $s4 = "return vFk9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}