rule sig_20161208_d1d92485d2144add5b400d227e88451e {
  meta:
    description = "datamaliciousorder - file 20161208_d1d92485d2144add5b400d227e88451e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d8e8fe36350e0abb9e25199ab65710072ad32330c5d77f7b920981415871aec"

  strings:
    $s1 = " new Date();vTHl1[\"setUTC\"+\"FullYear\"](\"2003\");if (vTHl1.getUTCFullYear().toString(10) == \"2003\") {var vPh9 = vPa2.split" ascii
    $s2 = "var vVLt6 = new Function(\"vPa2\", '{return vPa2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZf9 = new Function(\"vPa2" ascii
    $s3 = "; return vPh9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vVLt6 = new Function(\"vPa2\", '{return vPa2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZf9 = new Function(\"vPa2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}