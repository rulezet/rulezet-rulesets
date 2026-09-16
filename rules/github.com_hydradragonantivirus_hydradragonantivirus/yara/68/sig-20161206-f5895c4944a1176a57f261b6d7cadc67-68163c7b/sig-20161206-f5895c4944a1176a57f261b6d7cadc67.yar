rule sig_20161206_f5895c4944a1176a57f261b6d7cadc67 {
  meta:
    description = "datamaliciousorder - file 20161206_f5895c4944a1176a57f261b6d7cadc67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13e0a3c6adfc0b23ab5a172135722f8612c6ef2190ffa42714e4e73f00f44f2c"

  strings:
    $s1 = "var vVWr4 = new Function(\"s\", '{var vSv4 = new Date();vSv4[\"setUTCFullYear\"](\"2003\");if (vSv4.getUTCFullYear().toString(10" ascii
    $s2 = "var vVWr4 = new Function(\"s\", '{var vSv4 = new Date();vSv4[\"setUTCFullYear\"](\"2003\");if (vSv4.getUTCFullYear().toString(10" ascii
    $s3 = "function vZc3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vPXb6 = s.split(\"##\"); return vPXb6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}