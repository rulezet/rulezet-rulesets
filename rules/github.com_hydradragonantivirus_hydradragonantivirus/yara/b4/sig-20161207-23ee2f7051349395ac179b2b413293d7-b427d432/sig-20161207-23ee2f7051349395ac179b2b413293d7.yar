rule sig_20161207_23ee2f7051349395ac179b2b413293d7 {
  meta:
    description = "datamaliciousorder - file 20161207_23ee2f7051349395ac179b2b413293d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f487569eb724bc55772ed27b3683a39301c54297e13a0d1ce2f6eaf919934ecc"

  strings:
    $s1 = "var vTa2 = new Function(\"vCq0\", '{var vBOc2 = new Date();vBOc2[\"setUTCFullYear\"](\"2003\");if (vBOc2.getUTCFullYear().toStri" ascii
    $s2 = "var vTa2 = new Function(\"vCq0\", '{var vBOc2 = new Date();vBOc2[\"setUTCFullYear\"](\"2003\");if (vBOc2.getUTCFullYear().toStri" ascii
    $s3 = "var vKGe7 = new Function(\"vCq0\", '{return vCq0.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vGWi7 = vCq0.split(\"###\"); return vGWi7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}