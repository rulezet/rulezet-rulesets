rule sig_20161206_5846f7870e2d81ca4cc78826aa405bd0 {
  meta:
    description = "datamaliciousorder - file 20161206_5846f7870e2d81ca4cc78826aa405bd0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "064deba46e499babc8772e02f995211602ddcca0703249505f5b672a81283510"

  strings:
    $s1 = "var vODb1 = new Function(\"s\", '{var vUSg3 = new Date();vUSg3[\"setUTCFullYear\"](\"2003\");if (vUSg3.getUTCFullYear().toString" ascii
    $s2 = "var vODb1 = new Function(\"s\", '{var vUSg3 = new Date();vUSg3[\"setUTCFullYear\"](\"2003\");if (vUSg3.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vWPl6 = s.split(\"##\"); return vWPl6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vFLb9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}