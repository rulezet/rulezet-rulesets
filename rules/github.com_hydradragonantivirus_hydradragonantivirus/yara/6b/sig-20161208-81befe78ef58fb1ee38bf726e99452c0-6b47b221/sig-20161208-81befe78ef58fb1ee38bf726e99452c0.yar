rule sig_20161208_81befe78ef58fb1ee38bf726e99452c0 {
  meta:
    description = "datamaliciousorder - file 20161208_81befe78ef58fb1ee38bf726e99452c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a30c8d01c41f6af12e032d5a5b502383fd056bc23765b2cdd4a174c51e550343"

  strings:
    $s1 = "7 = new Date();vLKg7[\"setUTC\"+\"FullYear\"](\"2003\");if (vLKg7.getUTCFullYear().toString(10) == \"2003\") {var vOu0 = vMUb1.s" ascii
    $s2 = "var vHXc4 = new Function(\"vMUb1\", '{return vMUb1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZz9 = new Function(\"vMU" ascii
    $s3 = "var vHXc4 = new Function(\"vMUb1\", '{return vMUb1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZz9 = new Function(\"vMU" ascii
    $s4 = "##\"); return vOu0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}