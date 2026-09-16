rule sig_20161208_541f940d74169b9e0c7eae344d492a4e {
  meta:
    description = "datamaliciousorder - file 20161208_541f940d74169b9e0c7eae344d492a4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "727134d673d0ea44f8c9e0d6910324e5a39bd7749e95e85799fed34c70c2976f"

  strings:
    $s1 = "var vYo8 = new Function(\"vEYc0\", '{return vEYc0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGLq0 = new Function(\"vEY" ascii
    $s2 = "6 = new Date();vRLz6[\"setUTC\"+\"FullYear\"](\"2003\");if (vRLz6.getUTCFullYear().toString(10) == \"2003\") {var vQe7 = vEYc0.s" ascii
    $s3 = "##\"); return vQe7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vYo8 = new Function(\"vEYc0\", '{return vEYc0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGLq0 = new Function(\"vEY" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}