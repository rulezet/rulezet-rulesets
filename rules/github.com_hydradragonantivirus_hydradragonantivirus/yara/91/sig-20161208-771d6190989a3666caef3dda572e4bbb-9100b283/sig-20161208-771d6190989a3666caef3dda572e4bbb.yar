rule sig_20161208_771d6190989a3666caef3dda572e4bbb {
  meta:
    description = "datamaliciousorder - file 20161208_771d6190989a3666caef3dda572e4bbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5527d5927958c3ddcc6001c4d49a839d1b1635414159418ef829ab394c3f7ec"

  strings:
    $s1 = " new Date();vEe4[\"setUTC\"+\"FullYear\"](\"2003\");if (vEe4.getUTCFullYear().toString(10) == \"2003\") {var vLl6 = vXe3.split(" ascii
    $s2 = "var vJJv1 = new Function(\"vXe3\", '{return vXe3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTCf5 = new Function(\"vXe3" ascii
    $s3 = "return vLl6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vJJv1 = new Function(\"vXe3\", '{return vXe3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTCf5 = new Function(\"vXe3" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}