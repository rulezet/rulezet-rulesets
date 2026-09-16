rule sig_20161206_b9dc79707baa1b91c40cd1071242b95e {
  meta:
    description = "datamaliciousorder - file 20161206_b9dc79707baa1b91c40cd1071242b95e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97d72968cff60826cacd88a587c3059924182929424a45561478a85dfa659d9b"

  strings:
    $s1 = "var vSl1 = new Function(\"s\", '{var vORf4 = new Date();vORf4[\"setUTCFullYear\"](\"2003\");if (vORf4.getUTCFullYear().toString(" ascii
    $s2 = "var vSl1 = new Function(\"s\", '{var vORf4 = new Date();vORf4[\"setUTCFullYear\"](\"2003\");if (vORf4.getUTCFullYear().toString(" ascii
    $s3 = "function vFEw5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vHPp3 = s.split(\"##\"); return vHPp3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}