rule sig_20161208_e3386cedb9d5cd58a27d6e5f2a861415 {
  meta:
    description = "datamaliciousorder - file 20161208_e3386cedb9d5cd58a27d6e5f2a861415.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98665d871a8cbecb9fa5e1a7d7252c5efeb4f55a3a852f0e111fe37d69309b74"

  strings:
    $s1 = "x7 = new Date();vOPx7[\"setUTC\"+\"FullYear\"](\"2003\");if (vOPx7.getUTCFullYear().toString(10) == \"2003\") {var vMYj8 = vVKh3" ascii
    $s2 = "var vBGf4 = new Function(\"vVKh3\", '{return vVKh3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vASh9 = new Function(\"vV" ascii
    $s3 = "var vBGf4 = new Function(\"vVKh3\", '{return vVKh3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vASh9 = new Function(\"vV" ascii
    $s4 = "####\"); return vMYj8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}