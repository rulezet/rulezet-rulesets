rule sig_20161208_3449f4867b478e21a27f76f14712f5f3 {
  meta:
    description = "datamaliciousorder - file 20161208_3449f4867b478e21a27f76f14712f5f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c588fdbc6ec8573ce315888db0c1cd1e2da935386baa4950ef0f69ffc1ab71d0"

  strings:
    $s1 = "var vBNw1 = new Function(\"vXg4\", '{return vXg4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIf1 = new Function(\"vXg4" ascii
    $s2 = " new Date();vKGd1[\"setUTC\"+\"FullYear\"](\"2003\");if (vKGd1.getUTCFullYear().toString(10) == \"2003\") {var vXWn3 = vXg4.spli" ascii
    $s3 = "); return vXWn3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vBNw1 = new Function(\"vXg4\", '{return vXg4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIf1 = new Function(\"vXg4" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}