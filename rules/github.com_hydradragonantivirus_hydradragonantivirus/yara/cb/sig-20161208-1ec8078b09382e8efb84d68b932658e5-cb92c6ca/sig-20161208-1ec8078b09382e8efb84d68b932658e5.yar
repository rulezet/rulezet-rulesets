rule sig_20161208_1ec8078b09382e8efb84d68b932658e5 {
  meta:
    description = "datamaliciousorder - file 20161208_1ec8078b09382e8efb84d68b932658e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99c734b2cf652eb4c0ffb77b4b76c2eca82511e2e77180a66e1ec52669fa38a2"

  strings:
    $s1 = "new Date();vQUo6[\"setUTC\"+\"FullYear\"](\"2003\");if (vQUo6.getUTCFullYear().toString(10) == \"2003\") {var vZRk4 = vGc5.split" ascii
    $s2 = "var vFl9 = new Function(\"vGc5\", '{return vGc5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSy1 = new Function(\"vGc5\"" ascii
    $s3 = "var vFl9 = new Function(\"vGc5\", '{return vGc5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSy1 = new Function(\"vGc5\"" ascii
    $s4 = "; return vZRk4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}