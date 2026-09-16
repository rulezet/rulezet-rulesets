rule sig_20161208_f31b7e94b502b61c88abd5f507f874e2 {
  meta:
    description = "datamaliciousorder - file 20161208_f31b7e94b502b61c88abd5f507f874e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cad6d9c9a100061fd7a90c153ff855fa29945616bb4cdce913548a706c8c8d0"

  strings:
    $s1 = "var vFHc8 = new Function(\"vTh7\", '{return vTh7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIf3 = new Function(\"vTh7" ascii
    $s2 = " new Date();vQYk6[\"setUTC\"+\"FullYear\"](\"2003\");if (vQYk6.getUTCFullYear().toString(10) == \"2003\") {var vMh5 = vTh7.split" ascii
    $s3 = "var vFHc8 = new Function(\"vTh7\", '{return vTh7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIf3 = new Function(\"vTh7" ascii
    $s4 = "; return vMh5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}