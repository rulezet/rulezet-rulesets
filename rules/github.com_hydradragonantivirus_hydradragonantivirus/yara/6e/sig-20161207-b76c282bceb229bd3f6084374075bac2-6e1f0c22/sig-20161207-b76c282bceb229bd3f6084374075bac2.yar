rule sig_20161207_b76c282bceb229bd3f6084374075bac2 {
  meta:
    description = "datamaliciousorder - file 20161207_b76c282bceb229bd3f6084374075bac2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26d2f5173d11956f6b949df6b644476e46e2c1b8a012bbde17318040f863e576"

  strings:
    $s1 = "ew Date();vXn2[\"setUTCFullYear\"](\"2003\");if (vXn2.getUTCFullYear().toString(10) == \"2003\") {var vGx6 = vXp8.split(\"####\"" ascii
    $s2 = "var vXz5 = new Function(\"vXp8\", '{return vXp8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNy4 = new Function(\"vXp8\"" ascii
    $s3 = "n vGx6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vXz5 = new Function(\"vXp8\", '{return vXp8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNy4 = new Function(\"vXp8\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}