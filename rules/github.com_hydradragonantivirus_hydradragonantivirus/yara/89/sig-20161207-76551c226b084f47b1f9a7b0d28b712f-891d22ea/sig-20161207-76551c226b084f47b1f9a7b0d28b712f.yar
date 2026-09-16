rule sig_20161207_76551c226b084f47b1f9a7b0d28b712f {
  meta:
    description = "datamaliciousorder - file 20161207_76551c226b084f47b1f9a7b0d28b712f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc4177a51bd4dc1f3ca9b6be37869aed3719c50102c9bf7f64d3acd24f58c674"

  strings:
    $s1 = " = new Date();vMx5[\"setUTCFullYear\"](\"2003\");if (vMx5.getUTCFullYear().toString(10) == \"2003\") {var vYLk4 = vJAg3.split(\"" ascii
    $s2 = "var vKm2 = new Function(\"vJAg3\", '{return vJAg3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKUi5 = new Function(\"vJA" ascii
    $s3 = "var vKm2 = new Function(\"vJAg3\", '{return vJAg3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKUi5 = new Function(\"vJA" ascii
    $s4 = " return vYLk4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}