rule sig_20161208_1f8f97a73b4a2dbd9667be4c81c02832 {
  meta:
    description = "datamaliciousorder - file 20161208_1f8f97a73b4a2dbd9667be4c81c02832.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a434c854020b6c1cbf3d0d976fb305b9be2fe15778816aa0f05dd721df8f7c1"

  strings:
    $s1 = "var vTd4 = new Function(\"vQb2\", '{return vQb2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQGm7 = new Function(\"vQb2" ascii
    $s2 = " new Date();vCSg5[\"setUTC\"+\"FullYear\"](\"2003\");if (vCSg5.getUTCFullYear().toString(10) == \"2003\") {var vUBy7 = vQb2.spli" ascii
    $s3 = "); return vUBy7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vTd4 = new Function(\"vQb2\", '{return vQb2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQGm7 = new Function(\"vQb2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}