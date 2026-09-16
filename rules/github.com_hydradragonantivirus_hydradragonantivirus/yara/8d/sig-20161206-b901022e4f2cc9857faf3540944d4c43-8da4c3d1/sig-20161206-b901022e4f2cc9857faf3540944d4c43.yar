rule sig_20161206_b901022e4f2cc9857faf3540944d4c43 {
  meta:
    description = "datamaliciousorder - file 20161206_b901022e4f2cc9857faf3540944d4c43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6607be538a35c8e4fb1e8ca9824079bb81085aa3a15c5b1715294b2153f204c8"

  strings:
    $s1 = "var vENd2 = new Function(\"s\", '{var vSKp7 = new Date();vSKp7[\"setUTCFullYear\"](\"2003\");if (vSKp7.getUTCFullYear().toString" ascii
    $s2 = "var vENd2 = new Function(\"s\", '{var vSKp7 = new Date();vSKp7[\"setUTCFullYear\"](\"2003\");if (vSKp7.getUTCFullYear().toString" ascii
    $s3 = "function vIy9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vLQd2 = s.split(\"##\"); return vLQd2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}