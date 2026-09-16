rule sig_20161208_999aee536b06e3e63e84a1fbe71bb45c {
  meta:
    description = "datamaliciousorder - file 20161208_999aee536b06e3e63e84a1fbe71bb45c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ebab3f015dd325a4f35b8df9c875679e2218d35ea4730a5e857e4032cfab38d"

  strings:
    $s1 = "var vSQb9 = new Function(\"vOi3\", '{return vOi3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTj8 = new Function(\"vOi3" ascii
    $s2 = "new Date();vIw8[\"setUTC\"+\"FullYear\"](\"2003\");if (vIw8.getUTCFullYear().toString(10) == \"2003\") {var vTZs9 = vOi3.split(" ascii
    $s3 = "var vSQb9 = new Function(\"vOi3\", '{return vOi3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTj8 = new Function(\"vOi3" ascii
    $s4 = "return vTZs9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}