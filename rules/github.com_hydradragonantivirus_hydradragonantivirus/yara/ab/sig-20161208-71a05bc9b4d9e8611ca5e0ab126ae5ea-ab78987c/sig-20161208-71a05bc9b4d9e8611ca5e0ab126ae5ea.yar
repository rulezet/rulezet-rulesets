rule sig_20161208_71a05bc9b4d9e8611ca5e0ab126ae5ea {
  meta:
    description = "datamaliciousorder - file 20161208_71a05bc9b4d9e8611ca5e0ab126ae5ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "195b5184284bb91a613c8b893e3cbd3239f55dbb5d7db92a04640594897aca4d"

  strings:
    $s1 = "var vMYa5 = new Function(\"vBEk7\", '{return vBEk7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLe7 = new Function(\"vBE" ascii
    $s2 = "1 = new Date();vYFv1[\"setUTC\"+\"FullYear\"](\"2003\");if (vYFv1.getUTCFullYear().toString(10) == \"2003\") {var vMPl9 = vBEk7." ascii
    $s3 = "###\"); return vMPl9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vMYa5 = new Function(\"vBEk7\", '{return vBEk7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLe7 = new Function(\"vBE" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}