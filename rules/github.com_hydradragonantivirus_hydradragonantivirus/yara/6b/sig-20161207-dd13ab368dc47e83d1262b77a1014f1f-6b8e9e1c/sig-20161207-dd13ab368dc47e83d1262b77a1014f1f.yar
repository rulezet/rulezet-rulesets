rule sig_20161207_dd13ab368dc47e83d1262b77a1014f1f {
  meta:
    description = "datamaliciousorder - file 20161207_dd13ab368dc47e83d1262b77a1014f1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c932f9134ec4bd5d8c6d8cc92459e71474d90be8650ef78c191b673c01e45eb6"

  strings:
    $s1 = " new Date();vSFh9[\"setUTCFullYear\"](\"2003\");if (vSFh9.getUTCFullYear().toString(10) == \"2003\") {var vXu8 = vZl9.split(\"##" ascii
    $s2 = "var vPZc9 = new Function(\"vZl9\", '{return vZl9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRx1 = new Function(\"vZl9" ascii
    $s3 = "var vPZc9 = new Function(\"vZl9\", '{return vZl9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRx1 = new Function(\"vZl9" ascii
    $s4 = "eturn vXu8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}