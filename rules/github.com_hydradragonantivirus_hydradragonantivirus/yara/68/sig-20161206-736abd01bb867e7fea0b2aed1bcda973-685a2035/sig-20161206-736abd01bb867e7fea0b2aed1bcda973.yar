rule sig_20161206_736abd01bb867e7fea0b2aed1bcda973 {
  meta:
    description = "datamaliciousorder - file 20161206_736abd01bb867e7fea0b2aed1bcda973.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5571919fd873a0ece26a40d9a70518301ef50a391e32a33171f3abc2279f94ce"

  strings:
    $s1 = "var vWBx0 = new Function(\"s\", '{var vWm1 = new Date();vWm1[\"setUTCFullYear\"](\"2003\");if (vWm1.getUTCFullYear().toString(10" ascii
    $s2 = "var vWBx0 = new Function(\"s\", '{var vWm1 = new Date();vWm1[\"setUTCFullYear\"](\"2003\");if (vWm1.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vDk3 = s.split(\"##\"); return vDk3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vXAp7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}