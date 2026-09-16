rule sig_20161207_c9f9235b8340d644117ef45ecd1bfa30 {
  meta:
    description = "datamaliciousorder - file 20161207_c9f9235b8340d644117ef45ecd1bfa30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa989fa41208c11f86b1896de5bcf8b9089f4b8b231a33b18ad1dddf9ee764af"

  strings:
    $s1 = " = new Date();vLo4[\"setUTCFullYear\"](\"2003\");if (vLo4.getUTCFullYear().toString(10) == \"2003\") {var vOr5 = vKDb1.split(\"#" ascii
    $s2 = "var vGe4 = new Function(\"vKDb1\", '{return vKDb1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBQc0 = new Function(\"vKD" ascii
    $s3 = "return vOr5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vGe4 = new Function(\"vKDb1\", '{return vKDb1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBQc0 = new Function(\"vKD" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}