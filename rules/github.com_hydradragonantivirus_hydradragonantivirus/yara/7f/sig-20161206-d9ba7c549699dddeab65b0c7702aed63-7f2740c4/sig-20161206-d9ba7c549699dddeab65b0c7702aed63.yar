rule sig_20161206_d9ba7c549699dddeab65b0c7702aed63 {
  meta:
    description = "datamaliciousorder - file 20161206_d9ba7c549699dddeab65b0c7702aed63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fd05bd0db23457682d1c13bcf408789c6ce5b2bf54c6e13e964c79cbb92480b"

  strings:
    $s1 = "var vTVq4 = new Function(\"s\", '{var vSXs1 = new Date();vSXs1[\"setUTCFullYear\"](\"2003\");if (vSXs1.getUTCFullYear().toString" ascii
    $s2 = "var vTVq4 = new Function(\"s\", '{var vSXs1 = new Date();vSXs1[\"setUTCFullYear\"](\"2003\");if (vSXs1.getUTCFullYear().toString" ascii
    $s3 = "function vKQa0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vDZn0 = s.split(\"##\"); return vDZn0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}