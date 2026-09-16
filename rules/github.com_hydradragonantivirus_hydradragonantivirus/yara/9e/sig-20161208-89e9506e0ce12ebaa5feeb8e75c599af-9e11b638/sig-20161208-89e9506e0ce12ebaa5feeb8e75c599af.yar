rule sig_20161208_89e9506e0ce12ebaa5feeb8e75c599af {
  meta:
    description = "datamaliciousorder - file 20161208_89e9506e0ce12ebaa5feeb8e75c599af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6993262007a2e3f2668fc617373a1f2625404711de9b10ab1df36dadc6e2c00c"

  strings:
    $s1 = "= new Date();vIj3[\"setUTC\"+\"FullYear\"](\"2003\");if (vIj3.getUTCFullYear().toString(10) == \"2003\") {var vUBj1 = vQNz7.spli" ascii
    $s2 = "var vGb5 = new Function(\"vQNz7\", '{return vQNz7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXa6 = new Function(\"vQNz" ascii
    $s3 = "); return vUBj1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vGb5 = new Function(\"vQNz7\", '{return vQNz7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXa6 = new Function(\"vQNz" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}