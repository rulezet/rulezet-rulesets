rule sig_20161208_1b99ae776f1c0d435390f11b9515f555 {
  meta:
    description = "datamaliciousorder - file 20161208_1b99ae776f1c0d435390f11b9515f555.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01ebd105ef24c437b3d2af91265de57a8789fdf5d701612ea8aa892505c19c5c"

  strings:
    $s1 = "7 = new Date();vZDq7[\"setUTC\"+\"FullYear\"](\"2003\");if (vZDq7.getUTCFullYear().toString(10) == \"2003\") {var vCDm6 = vPDo1." ascii
    $s2 = "var vGCn4 = new Function(\"vPDo1\", '{return vPDo1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXm7 = new Function(\"vPD" ascii
    $s3 = "###\"); return vCDm6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vGCn4 = new Function(\"vPDo1\", '{return vPDo1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXm7 = new Function(\"vPD" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}