rule sig_20161208_76574a62b7c1e9d09474de6f6b273b5b {
  meta:
    description = "datamaliciousorder - file 20161208_76574a62b7c1e9d09474de6f6b273b5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5cc44c38e6a82a8d309085daababc26888721fe24c0f07410f36132cfdb9bae"

  strings:
    $s1 = "var vKHm6 = new Function(\"vEAr2\", '{return vEAr2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVb1 = new Function(\"vEA" ascii
    $s2 = "2 = new Date();vCXj2[\"setUTC\"+\"FullYear\"](\"2003\");if (vCXj2.getUTCFullYear().toString(10) == \"2003\") {var vPu6 = vEAr2.s" ascii
    $s3 = "##\"); return vPu6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vKHm6 = new Function(\"vEAr2\", '{return vEAr2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVb1 = new Function(\"vEA" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}