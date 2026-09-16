rule sig_20161208_11418e0b1e7a571b47450ecc176f993b {
  meta:
    description = "datamaliciousorder - file 20161208_11418e0b1e7a571b47450ecc176f993b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c31f1ff788dcf7f85129d3613edbe35cd586e6a15571cf9969e1fe60e2ec9cc0"

  strings:
    $s1 = "var vERk1 = new Function(\"vPIu1\", '{return vPIu1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRFk9 = new Function(\"vP" ascii
    $s2 = "y8 = new Date();vJEy8[\"setUTC\"+\"FullYear\"](\"2003\");if (vJEy8.getUTCFullYear().toString(10) == \"2003\") {var vZo6 = vPIu1." ascii
    $s3 = "var vERk1 = new Function(\"vPIu1\", '{return vPIu1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRFk9 = new Function(\"vP" ascii
    $s4 = "###\"); return vZo6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}