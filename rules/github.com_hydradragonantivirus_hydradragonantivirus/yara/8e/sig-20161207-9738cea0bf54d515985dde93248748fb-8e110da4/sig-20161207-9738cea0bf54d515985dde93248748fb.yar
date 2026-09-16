rule sig_20161207_9738cea0bf54d515985dde93248748fb {
  meta:
    description = "datamaliciousorder - file 20161207_9738cea0bf54d515985dde93248748fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7e760e33b1028bba2b58d805ce43d01a3a512efc2629563296e7418d49f06ce"

  strings:
    $s1 = "var vMAu9 = new Function(\"vJh7\", '{var vJWx7 = new Date();vJWx7[\"setUTCFullYear\"](\"2003\");if (vJWx7.getUTCFullYear().toStr" ascii
    $s2 = "var vMAu9 = new Function(\"vJh7\", '{var vJWx7 = new Date();vJWx7[\"setUTCFullYear\"](\"2003\");if (vJWx7.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vCQj4 = vJh7.split(\"###\"); return vCQj4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vIWr6 = new Function(\"vJh7\", '{return vJh7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}