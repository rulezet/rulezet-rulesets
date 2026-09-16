rule sig_20161207_cded6942579a291f222fc1a2e8c12b42 {
  meta:
    description = "datamaliciousorder - file 20161207_cded6942579a291f222fc1a2e8c12b42.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc571b3c28901e03db2fa3c7ec03da489448b7046624c66c531ae640d4a49e0a"

  strings:
    $s1 = "var vYBs0 = new Function(\"vKXk1\", '{var vSMl1 = new Date();vSMl1[\"setUTCFullYear\"](\"2003\");if (vSMl1.getUTCFullYear().toSt" ascii
    $s2 = "var vYBs0 = new Function(\"vKXk1\", '{var vSMl1 = new Date();vSMl1[\"setUTCFullYear\"](\"2003\");if (vSMl1.getUTCFullYear().toSt" ascii
    $s3 = "var vRHg8 = new Function(\"vKXk1\", '{return vKXk1.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "0) == \"2003\") {var vVv1 = vKXk1.split(\"###\"); return vVv1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}