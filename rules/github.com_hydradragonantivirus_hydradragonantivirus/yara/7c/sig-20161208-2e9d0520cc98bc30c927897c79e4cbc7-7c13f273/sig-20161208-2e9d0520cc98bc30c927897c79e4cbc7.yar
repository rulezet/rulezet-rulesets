rule sig_20161208_2e9d0520cc98bc30c927897c79e4cbc7 {
  meta:
    description = "datamaliciousorder - file 20161208_2e9d0520cc98bc30c927897c79e4cbc7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "257be3f60b248415357918d6d1f2e97a70f2d51c5e9140045997909161102e95"

  strings:
    $s1 = "8 = new Date();vQv8[\"setUTC\"+\"FullYear\"](\"2003\");if (vQv8.getUTCFullYear().toString(10) == \"2003\") {var vIZz9 = vQDi9.sp" ascii
    $s2 = "var vFJv9 = new Function(\"vQDi9\", '{return vQDi9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVZk1 = new Function(\"vQ" ascii
    $s3 = "var vFJv9 = new Function(\"vQDi9\", '{return vQDi9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVZk1 = new Function(\"vQ" ascii
    $s4 = "#\"); return vIZz9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}