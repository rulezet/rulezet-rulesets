rule sig_20161208_025460e127f88bf2b9da672367934270 {
  meta:
    description = "datamaliciousorder - file 20161208_025460e127f88bf2b9da672367934270.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e737b94b7072ccd07c3d1da39ba03aa4ea2622c7a903b78277f1bed2522adb75"

  strings:
    $s1 = " = new Date();vLLg2[\"setUTC\"+\"FullYear\"](\"2003\");if (vLLg2.getUTCFullYear().toString(10) == \"2003\") {var vSi2 = vDJt2.sp" ascii
    $s2 = "var vEn3 = new Function(\"vDJt2\", '{return vDJt2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTi9 = new Function(\"vDJt" ascii
    $s3 = "#\"); return vSi2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEn3 = new Function(\"vDJt2\", '{return vDJt2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTi9 = new Function(\"vDJt" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}