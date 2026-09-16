rule sig_20161207_50bb8de027e41326bc0511ec7688d8c1 {
  meta:
    description = "datamaliciousorder - file 20161207_50bb8de027e41326bc0511ec7688d8c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0775c6da7ea979e10cae86073d3e33e5ffdd1af763d8a356d898aba9ce171875"

  strings:
    $s1 = "var vAWw3 = new Function(\"vKj4\", '{return vKj4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMCm9 = new Function(\"vKj4" ascii
    $s2 = " new Date();vPl2[\"setUTCFullYear\"](\"2003\");if (vPl2.getUTCFullYear().toString(10) == \"2003\") {var vTh2 = vKj4.split(\"####" ascii
    $s3 = "urn vTh2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vAWw3 = new Function(\"vKj4\", '{return vKj4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMCm9 = new Function(\"vKj4" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}