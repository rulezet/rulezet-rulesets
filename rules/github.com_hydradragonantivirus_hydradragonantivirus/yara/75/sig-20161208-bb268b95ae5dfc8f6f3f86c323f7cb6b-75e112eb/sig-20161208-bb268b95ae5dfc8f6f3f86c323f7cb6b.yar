rule sig_20161208_bb268b95ae5dfc8f6f3f86c323f7cb6b {
  meta:
    description = "datamaliciousorder - file 20161208_bb268b95ae5dfc8f6f3f86c323f7cb6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e45b2d751ed93c094a0c76afd6c23d971fd77c94f9562d5984f54af5b62f1b86"

  strings:
    $s1 = "new Date();vWu1[\"setUTC\"+\"FullYear\"](\"2003\");if (vWu1.getUTCFullYear().toString(10) == \"2003\") {var vGSy8 = vMv3.split(" ascii
    $s2 = "var vGAq9 = new Function(\"vMv3\", '{return vMv3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZu4 = new Function(\"vMv3" ascii
    $s3 = "return vGSy8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vGAq9 = new Function(\"vMv3\", '{return vMv3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZu4 = new Function(\"vMv3" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}