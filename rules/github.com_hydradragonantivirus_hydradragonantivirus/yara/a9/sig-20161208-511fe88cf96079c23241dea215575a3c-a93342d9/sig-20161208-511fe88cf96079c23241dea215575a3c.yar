rule sig_20161208_511fe88cf96079c23241dea215575a3c {
  meta:
    description = "datamaliciousorder - file 20161208_511fe88cf96079c23241dea215575a3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6edd571e74750267e560fe158ebbea3b9bd5788a5c7e074025c6f8f8c8c43c4"

  strings:
    $s1 = "3 = new Date();vQVd3[\"setUTC\"+\"FullYear\"](\"2003\");if (vQVd3.getUTCFullYear().toString(10) == \"2003\") {var vHt9 = vFKf0.s" ascii
    $s2 = "var vBWn7 = new Function(\"vFKf0\", '{return vFKf0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGx3 = new Function(\"vFK" ascii
    $s3 = "var vBWn7 = new Function(\"vFKf0\", '{return vFKf0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGx3 = new Function(\"vFK" ascii
    $s4 = "##\"); return vHt9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}