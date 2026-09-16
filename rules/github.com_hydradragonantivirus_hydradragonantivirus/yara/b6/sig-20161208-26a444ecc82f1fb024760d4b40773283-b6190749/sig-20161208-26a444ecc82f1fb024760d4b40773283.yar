rule sig_20161208_26a444ecc82f1fb024760d4b40773283 {
  meta:
    description = "datamaliciousorder - file 20161208_26a444ecc82f1fb024760d4b40773283.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52e5290433f0db747b5ff62d2e30fd0db4acff4bb1e6e8df9281fe8b95cb8ea8"

  strings:
    $s1 = "ew Date();vZk3[\"setUTC\"+\"FullYear\"](\"2003\");if (vZk3.getUTCFullYear().toString(10) == \"2003\") {var vTIn1 = vMi0.split(\"" ascii
    $s2 = "var vHa3 = new Function(\"vMi0\", '{return vMi0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMv2 = new Function(\"vMi0\"" ascii
    $s3 = "var vHa3 = new Function(\"vMi0\", '{return vMi0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMv2 = new Function(\"vMi0\"" ascii
    $s4 = "eturn vTIn1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}