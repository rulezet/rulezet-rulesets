rule sig_20161207_d178d24caabca25a239343e90293daef {
  meta:
    description = "datamaliciousorder - file 20161207_d178d24caabca25a239343e90293daef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60d685d8c0803c0c6420d2672e670d1d9a53aff622a16f54709bfa5be902747a"

  strings:
    $s1 = "var vCi7 = new Function(\"vKKe7\", '{var vLn0 = new Date();vLn0[\"setUTCFullYear\"](\"2003\");if (vLn0.getUTCFullYear().toString" ascii
    $s2 = "var vCi7 = new Function(\"vKKe7\", '{var vLn0 = new Date();vLn0[\"setUTCFullYear\"](\"2003\");if (vLn0.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vDm3 = vKKe7.split(\"###\"); return vDm3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vTp8 = new Function(\"vKKe7\", '{return vKKe7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}