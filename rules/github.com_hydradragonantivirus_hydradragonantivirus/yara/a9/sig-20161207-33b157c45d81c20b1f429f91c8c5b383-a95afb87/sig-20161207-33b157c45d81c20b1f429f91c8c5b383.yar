rule sig_20161207_33b157c45d81c20b1f429f91c8c5b383 {
  meta:
    description = "datamaliciousorder - file 20161207_33b157c45d81c20b1f429f91c8c5b383.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e750f876eceaf9bb5f5dcc682a29cd3215009ac1240007d74798595b890d31a"

  strings:
    $s1 = " new Date();vXOt6[\"setUTCFullYear\"](\"2003\");if (vXOt6.getUTCFullYear().toString(10) == \"2003\") {var vPz6 = vGi3.split(\"##" ascii
    $s2 = "var vWg4 = new Function(\"vGi3\", '{return vGi3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNJu0 = new Function(\"vGi3" ascii
    $s3 = "eturn vPz6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vWg4 = new Function(\"vGi3\", '{return vGi3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNJu0 = new Function(\"vGi3" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}