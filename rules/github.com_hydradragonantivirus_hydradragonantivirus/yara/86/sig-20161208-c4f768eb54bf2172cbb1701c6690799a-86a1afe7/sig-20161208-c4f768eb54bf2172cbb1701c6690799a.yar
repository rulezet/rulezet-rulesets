rule sig_20161208_c4f768eb54bf2172cbb1701c6690799a {
  meta:
    description = "datamaliciousorder - file 20161208_c4f768eb54bf2172cbb1701c6690799a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71e79427adbec3cddb9f37d776ce56491117c58c05adfa079af7ab7b4c6f8005"

  strings:
    $s1 = "var vWu5 = new Function(\"vSa8\", '{return vSa8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRw3 = new Function(\"vSa8\"" ascii
    $s2 = "ew Date();vGl5[\"setUTC\"+\"FullYear\"](\"2003\");if (vGl5.getUTCFullYear().toString(10) == \"2003\") {var vZBv0 = vSa8.split(\"" ascii
    $s3 = "var vWu5 = new Function(\"vSa8\", '{return vSa8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRw3 = new Function(\"vSa8\"" ascii
    $s4 = "eturn vZBv0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}