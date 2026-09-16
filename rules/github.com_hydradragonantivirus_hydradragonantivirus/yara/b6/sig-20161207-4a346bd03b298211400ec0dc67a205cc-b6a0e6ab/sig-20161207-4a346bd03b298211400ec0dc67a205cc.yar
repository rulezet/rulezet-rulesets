rule sig_20161207_4a346bd03b298211400ec0dc67a205cc {
  meta:
    description = "datamaliciousorder - file 20161207_4a346bd03b298211400ec0dc67a205cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d62a38704622108c788eacfc988fa5cf28079e30d91d83782595edfa56be303"

  strings:
    $s1 = "var vFCk9 = new Function(\"vSv7\", '{var vTh6 = new Date();vTh6[\"setUTCFullYear\"](\"2003\");if (vTh6.getUTCFullYear().toString" ascii
    $s2 = "var vFCk9 = new Function(\"vSv7\", '{var vTh6 = new Date();vTh6[\"setUTCFullYear\"](\"2003\");if (vTh6.getUTCFullYear().toString" ascii
    $s3 = "var vVEj0 = new Function(\"vSv7\", '{return vSv7.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vMo3 = vSv7.split(\"###\"); return vMo3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}