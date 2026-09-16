rule sig_20161206_897861ca475f188581a4b260845d1947 {
  meta:
    description = "datamaliciousorder - file 20161206_897861ca475f188581a4b260845d1947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4681e073415e460f3ff153c957cd781ac67f5dc8e61149e4a7e52cdb081a4e9"

  strings:
    $s1 = "var vFHe1 = new Function(\"s\", '{var vFYs1 = new Date();vFYs1[\"setUTCFullYear\"](\"2003\");if (vFYs1.getUTCFullYear().toString" ascii
    $s2 = "var vFHe1 = new Function(\"s\", '{var vFYs1 = new Date();vFYs1[\"setUTCFullYear\"](\"2003\");if (vFYs1.getUTCFullYear().toString" ascii
    $s3 = "function vEJe1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vGy4 = s.split(\"##\"); return vGy4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}