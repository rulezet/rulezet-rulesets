rule sig_20161207_b790df25e57dd0ccef5d30fbcafc3389 {
  meta:
    description = "datamaliciousorder - file 20161207_b790df25e57dd0ccef5d30fbcafc3389.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b91fee3eea668d324d232bfd8b4d906bcbb4ad162f7765d7dbe078d322d6076d"

  strings:
    $s1 = "var vPFr2 = new Function(\"vHTw9\", '{var vJOy5 = new Date();vJOy5[\"setUTCFullYear\"](\"2003\");if (vJOy5.getUTCFullYear().toSt" ascii
    $s2 = "var vPFr2 = new Function(\"vHTw9\", '{var vJOy5 = new Date();vJOy5[\"setUTCFullYear\"](\"2003\");if (vJOy5.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vVKd3 = vHTw9.split(\"###\"); return vVKd3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vCLa0 = new Function(\"vHTw9\", '{return vHTw9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}