rule sig_20161207_b3609847114f9097619dbd1646a5f04f {
  meta:
    description = "datamaliciousorder - file 20161207_b3609847114f9097619dbd1646a5f04f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe16f0cf1bd721bc849162e3b4d51cf4eda83267207679a1daaf6063a6325d1d"

  strings:
    $s1 = "var vWPh2 = new Function(\"vEAl5\", '{var vWg3 = new Date();vWg3[\"setUTCFullYear\"](\"2003\");if (vWg3.getUTCFullYear().toStrin" ascii
    $s2 = "var vWPh2 = new Function(\"vEAl5\", '{var vWg3 = new Date();vWg3[\"setUTCFullYear\"](\"2003\");if (vWg3.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vROw2 = vEAl5.split(\"###\"); return vROw2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vFVr7 = new Function(\"vEAl5\", '{return vEAl5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}