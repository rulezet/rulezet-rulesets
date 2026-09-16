rule sig_20161207_81a640fcadf1b6cfaf69d28244d274ce {
  meta:
    description = "datamaliciousorder - file 20161207_81a640fcadf1b6cfaf69d28244d274ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afd28a59c3a01dd458e51b7a8bf2dc66149e4e37b99c8eefff3dbeaf5aad2d16"

  strings:
    $s1 = "ew Date();vUq2[\"setUTCFullYear\"](\"2003\");if (vUq2.getUTCFullYear().toString(10) == \"2003\") {var vWCr1 = vXo1.split(\"####" ascii
    $s2 = "var vNb8 = new Function(\"vXo1\", '{return vXo1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAn4 = new Function(\"vXo1\"" ascii
    $s3 = "var vNb8 = new Function(\"vXo1\", '{return vXo1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAn4 = new Function(\"vXo1\"" ascii
    $s4 = "rn vWCr1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}