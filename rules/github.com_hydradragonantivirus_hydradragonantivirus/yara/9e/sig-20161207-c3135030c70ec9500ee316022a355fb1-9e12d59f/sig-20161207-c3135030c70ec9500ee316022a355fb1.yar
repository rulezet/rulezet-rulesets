rule sig_20161207_c3135030c70ec9500ee316022a355fb1 {
  meta:
    description = "datamaliciousorder - file 20161207_c3135030c70ec9500ee316022a355fb1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2eb19bc35f8b8fa6ffacb6131730aa2bf2ac699b507d201630d1a1a92212b5e"

  strings:
    $s1 = "var vEy8 = new Function(\"vOk7\", '{return vOk7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNj9 = new Function(\"vOk7\"" ascii
    $s2 = "ew Date();vQq1[\"setUTCFullYear\"](\"2003\");if (vQq1.getUTCFullYear().toString(10) == \"2003\") {var vZh5 = vOk7.split(\"####\"" ascii
    $s3 = "n vZh5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEy8 = new Function(\"vOk7\", '{return vOk7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNj9 = new Function(\"vOk7\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}