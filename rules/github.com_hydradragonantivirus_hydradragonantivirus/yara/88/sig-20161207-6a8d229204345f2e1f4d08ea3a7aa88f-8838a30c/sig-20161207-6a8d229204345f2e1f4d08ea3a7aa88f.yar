rule sig_20161207_6a8d229204345f2e1f4d08ea3a7aa88f {
  meta:
    description = "datamaliciousorder - file 20161207_6a8d229204345f2e1f4d08ea3a7aa88f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbe47c236a189224b584ebfaa3f272a12c3b7f9a90201f95cb8ec0b23114a8e9"

  strings:
    $s1 = " = new Date();vSx6[\"setUTCFullYear\"](\"2003\");if (vSx6.getUTCFullYear().toString(10) == \"2003\") {var vACd7 = vCNh5.split(\"" ascii
    $s2 = "var vEj2 = new Function(\"vCNh5\", '{return vCNh5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUDl0 = new Function(\"vCN" ascii
    $s3 = " return vACd7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEj2 = new Function(\"vCNh5\", '{return vCNh5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUDl0 = new Function(\"vCN" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}