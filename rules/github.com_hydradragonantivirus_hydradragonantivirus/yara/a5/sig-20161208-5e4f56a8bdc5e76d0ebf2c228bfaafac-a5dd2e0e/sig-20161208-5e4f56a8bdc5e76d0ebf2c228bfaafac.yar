rule sig_20161208_5e4f56a8bdc5e76d0ebf2c228bfaafac {
  meta:
    description = "datamaliciousorder - file 20161208_5e4f56a8bdc5e76d0ebf2c228bfaafac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d97a3689a79918967f9fc07ac05ca019931740a88eee5d5eba750668f575336b"

  strings:
    $s1 = "j0 = new Date();vQSj0[\"setUTC\"+\"FullYear\"](\"2003\");if (vQSj0.getUTCFullYear().toString(10) == \"2003\") {var vZQy7 = vIUp4" ascii
    $s2 = "var vKMa5 = new Function(\"vIUp4\", '{return vIUp4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHZo5 = new Function(\"vI" ascii
    $s3 = "####\"); return vZQy7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vKMa5 = new Function(\"vIUp4\", '{return vIUp4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHZo5 = new Function(\"vI" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}