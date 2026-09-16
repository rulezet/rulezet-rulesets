rule sig_20161208_06e592cfaab831e3a8ebdfa28cc3c547 {
  meta:
    description = "datamaliciousorder - file 20161208_06e592cfaab831e3a8ebdfa28cc3c547.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "635680a66241f3d6d0294006c87278bf90705c966faeeb552dd41b9b7833a236"

  strings:
    $s1 = "4 = new Date();vMXg4[\"setUTC\"+\"FullYear\"](\"2003\");if (vMXg4.getUTCFullYear().toString(10) == \"2003\") {var vIp8 = vFVi1.s" ascii
    $s2 = "var vRr3 = new Function(\"vFVi1\", '{return vFVi1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAAk2 = new Function(\"vFV" ascii
    $s3 = "var vRr3 = new Function(\"vFVi1\", '{return vFVi1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAAk2 = new Function(\"vFV" ascii
    $s4 = "##\"); return vIp8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}