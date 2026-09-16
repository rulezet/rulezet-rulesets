rule sig_20161207_ab58fb1a8759b642c421e7b03e3a713a {
  meta:
    description = "datamaliciousorder - file 20161207_ab58fb1a8759b642c421e7b03e3a713a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c69cb627015460e81b597a38e10cfa7e0fa3b260dec16b301142f10bc6384ba3"

  strings:
    $s1 = "= new Date();vFf5[\"setUTCFullYear\"](\"2003\");if (vFf5.getUTCFullYear().toString(10) == \"2003\") {var vWPp6 = vUTc1.split(\"#" ascii
    $s2 = "var vHw4 = new Function(\"vUTc1\", '{return vUTc1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMr4 = new Function(\"vUTc" ascii
    $s3 = "var vHw4 = new Function(\"vUTc1\", '{return vUTc1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMr4 = new Function(\"vUTc" ascii
    $s4 = "return vWPp6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}