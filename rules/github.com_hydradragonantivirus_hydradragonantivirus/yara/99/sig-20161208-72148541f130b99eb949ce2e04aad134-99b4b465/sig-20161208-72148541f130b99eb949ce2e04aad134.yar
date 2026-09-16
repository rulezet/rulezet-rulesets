rule sig_20161208_72148541f130b99eb949ce2e04aad134 {
  meta:
    description = "datamaliciousorder - file 20161208_72148541f130b99eb949ce2e04aad134.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1e95f2afe9cf2ab21ac94e30708b5cd250db0c37d3d2bbc55885cdfc6b62639"

  strings:
    $s1 = "var vEz3 = new Function(\"vFa9\", '{return vFa9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEa9 = new Function(\"vFa9\"" ascii
    $s2 = "new Date();vRTg0[\"setUTC\"+\"FullYear\"](\"2003\");if (vRTg0.getUTCFullYear().toString(10) == \"2003\") {var vSi1 = vFa9.split(" ascii
    $s3 = " return vSi1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEz3 = new Function(\"vFa9\", '{return vFa9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEa9 = new Function(\"vFa9\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}