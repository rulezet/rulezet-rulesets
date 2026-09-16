rule sig_20161207_c7c6b7065cb5090f51aca77c934661fa {
  meta:
    description = "datamaliciousorder - file 20161207_c7c6b7065cb5090f51aca77c934661fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5df191741b31ea85b50b8f553b3964ade2b4d45f36347edc2cf5c14bb4674b08"

  strings:
    $s1 = "var vBAo9 = new Function(\"vZs4\", '{return vZs4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCe0 = new Function(\"vZs4" ascii
    $s2 = " new Date();vFWh1[\"setUTCFullYear\"](\"2003\");if (vFWh1.getUTCFullYear().toString(10) == \"2003\") {var vCx6 = vZs4.split(\"##" ascii
    $s3 = "eturn vCx6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vBAo9 = new Function(\"vZs4\", '{return vZs4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCe0 = new Function(\"vZs4" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}