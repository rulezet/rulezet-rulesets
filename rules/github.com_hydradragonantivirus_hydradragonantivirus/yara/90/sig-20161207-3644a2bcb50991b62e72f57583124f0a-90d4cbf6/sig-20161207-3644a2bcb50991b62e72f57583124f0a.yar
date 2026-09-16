rule sig_20161207_3644a2bcb50991b62e72f57583124f0a {
  meta:
    description = "datamaliciousorder - file 20161207_3644a2bcb50991b62e72f57583124f0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e23d65ad42aabe43cecc240f0ee6f9f25af2edc42646f7573137e03717118dbf"

  strings:
    $s1 = "var vZk5 = new Function(\"vPMy2\", '{return vPMy2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIi8 = new Function(\"vPMy" ascii
    $s2 = "= new Date();vZk1[\"setUTCFullYear\"](\"2003\");if (vZk1.getUTCFullYear().toString(10) == \"2003\") {var vLn3 = vPMy2.split(\"##" ascii
    $s3 = "eturn vLn3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vZk5 = new Function(\"vPMy2\", '{return vPMy2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIi8 = new Function(\"vPMy" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}