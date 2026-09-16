rule sig_20161208_763f8222f6f7fe84ea7425f2727832c2 {
  meta:
    description = "datamaliciousorder - file 20161208_763f8222f6f7fe84ea7425f2727832c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "383a8f833d3ff78e1dfeb48dc60f771c26c54ccb55cf51231f5620d33f9de332"

  strings:
    $s1 = "new Date();vNi8[\"setUTC\"+\"FullYear\"](\"2003\");if (vNi8.getUTCFullYear().toString(10) == \"2003\") {var vCCm1 = vOc3.split(" ascii
    $s2 = "var vYb8 = new Function(\"vOc3\", '{return vOc3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTMo5 = new Function(\"vOc3" ascii
    $s3 = "return vCCm1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vYb8 = new Function(\"vOc3\", '{return vOc3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTMo5 = new Function(\"vOc3" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}