rule sig_20161207_47946aeacac0cb13b31a565dfb4d6932 {
  meta:
    description = "datamaliciousorder - file 20161207_47946aeacac0cb13b31a565dfb4d6932.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e839b15bf47a913556a553eef8b928ab94949d7b29feed0026d3b155989a028"

  strings:
    $s1 = "var vSNe0 = new Function(\"vWh5\", '{return vWh5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJMi5 = new Function(\"vWh5" ascii
    $s2 = " new Date();vBf0[\"setUTCFullYear\"](\"2003\");if (vBf0.getUTCFullYear().toString(10) == \"2003\") {var vZh4 = vWh5.split(\"####" ascii
    $s3 = "urn vZh4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vSNe0 = new Function(\"vWh5\", '{return vWh5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJMi5 = new Function(\"vWh5" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}