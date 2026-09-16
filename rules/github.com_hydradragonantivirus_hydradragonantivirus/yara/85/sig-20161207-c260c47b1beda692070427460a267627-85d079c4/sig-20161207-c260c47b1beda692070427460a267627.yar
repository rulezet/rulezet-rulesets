rule sig_20161207_c260c47b1beda692070427460a267627 {
  meta:
    description = "datamaliciousorder - file 20161207_c260c47b1beda692070427460a267627.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f120b7bd6700a93c51722d32b9f113246d8c9cfe1f740cfe8e6783d6f435ff67"

  strings:
    $s1 = "var vGz5 = new Function(\"vMHy0\", '{var vRt5 = new Date();vRt5[\"setUTCFullYear\"](\"2003\");if (vRt5.getUTCFullYear().toString" ascii
    $s2 = "var vGz5 = new Function(\"vMHy0\", '{var vRt5 = new Date();vRt5[\"setUTCFullYear\"](\"2003\");if (vRt5.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vMa1 = vMHy0.split(\"###\"); return vMa1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vVBu6 = new Function(\"vMHy0\", '{return vMHy0.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}