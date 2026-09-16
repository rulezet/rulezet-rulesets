rule sig_20161208_19bb5e0f327645b3faac0fb0b4f5669a {
  meta:
    description = "datamaliciousorder - file 20161208_19bb5e0f327645b3faac0fb0b4f5669a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96c5eca52e583f19d626413690ea056292e0bdd190bbe03f570e5d6bc63e819b"

  strings:
    $s1 = "7 = new Date();vOMz7[\"setUTC\"+\"FullYear\"](\"2003\");if (vOMz7.getUTCFullYear().toString(10) == \"2003\") {var vRIr0 = vWOw5." ascii
    $s2 = "var vKa2 = new Function(\"vWOw5\", '{return vWOw5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHZd8 = new Function(\"vWO" ascii
    $s3 = "var vKa2 = new Function(\"vWOw5\", '{return vWOw5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHZd8 = new Function(\"vWO" ascii
    $s4 = "###\"); return vRIr0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}