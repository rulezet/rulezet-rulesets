rule sig_20161208_a3547f87c84cea860a35f2eba184e66d {
  meta:
    description = "datamaliciousorder - file 20161208_a3547f87c84cea860a35f2eba184e66d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6337b02f9bdbe21c364f7ba851ac8ae898c3979da899e1d9f72a8cb388c98e1a"

  strings:
    $s1 = "var vEn0 = new Function(\"vOVh5\", '{return vOVh5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFCc9 = new Function(\"vOV" ascii
    $s2 = "3 = new Date();vUKd3[\"setUTC\"+\"FullYear\"](\"2003\");if (vUKd3.getUTCFullYear().toString(10) == \"2003\") {var vMe6 = vOVh5.s" ascii
    $s3 = "##\"); return vMe6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEn0 = new Function(\"vOVh5\", '{return vOVh5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFCc9 = new Function(\"vOV" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}