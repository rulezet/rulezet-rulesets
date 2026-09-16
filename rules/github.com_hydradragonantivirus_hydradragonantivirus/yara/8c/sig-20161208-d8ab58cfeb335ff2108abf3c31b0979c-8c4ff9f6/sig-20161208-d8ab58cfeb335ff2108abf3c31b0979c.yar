rule sig_20161208_d8ab58cfeb335ff2108abf3c31b0979c {
  meta:
    description = "datamaliciousorder - file 20161208_d8ab58cfeb335ff2108abf3c31b0979c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d42c7db9ff87c99847dd5491691b2f96a40cd5f925af04c5f6881a3f9509674"

  strings:
    $s1 = "7 = new Date();vXy7[\"setUTC\"+\"FullYear\"](\"2003\");if (vXy7.getUTCFullYear().toString(10) == \"2003\") {var vWJm0 = vPWp5.sp" ascii
    $s2 = "var vTRt1 = new Function(\"vPWp5\", '{return vPWp5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBHr6 = new Function(\"vP" ascii
    $s3 = "#\"); return vWJm0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vTRt1 = new Function(\"vPWp5\", '{return vPWp5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBHr6 = new Function(\"vP" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}