rule sig_20161207_b9d2344afb0e10da08bf014b78ab9b74 {
  meta:
    description = "datamaliciousorder - file 20161207_b9d2344afb0e10da08bf014b78ab9b74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "601bf33db2c8a755c5ee4ce09ee95b943d7ffba15f2bc003a7c7bf6db9daf858"

  strings:
    $s1 = "var vGf7 = new Function(\"vLEm3\", '{return vLEm3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDAv6 = new Function(\"vLE" ascii
    $s2 = " = new Date();vXx8[\"setUTCFullYear\"](\"2003\");if (vXx8.getUTCFullYear().toString(10) == \"2003\") {var vYb0 = vLEm3.split(\"#" ascii
    $s3 = "return vYb0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vGf7 = new Function(\"vLEm3\", '{return vLEm3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDAv6 = new Function(\"vLE" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}