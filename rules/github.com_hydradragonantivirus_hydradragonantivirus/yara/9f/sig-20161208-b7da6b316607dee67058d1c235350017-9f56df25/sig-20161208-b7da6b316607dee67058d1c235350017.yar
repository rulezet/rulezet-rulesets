rule sig_20161208_b7da6b316607dee67058d1c235350017 {
  meta:
    description = "datamaliciousorder - file 20161208_b7da6b316607dee67058d1c235350017.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f157dfd8b21fc56cd28eee80b955569100d40f83c3a22a64dbab79ddaccc458f"

  strings:
    $s1 = "var vTGa3 = new Function(\"vIUf3\", '{return vIUf3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBz2 = new Function(\"vIU" ascii
    $s2 = " = new Date();vDj5[\"setUTC\"+\"FullYear\"](\"2003\");if (vDj5.getUTCFullYear().toString(10) == \"2003\") {var vAe7 = vIUf3.spli" ascii
    $s3 = "var vTGa3 = new Function(\"vIUf3\", '{return vIUf3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBz2 = new Function(\"vIU" ascii
    $s4 = "); return vAe7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}