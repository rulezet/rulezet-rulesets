rule sig_20161206_85c293906f1b1c05ed0539a0ef32646d {
  meta:
    description = "datamaliciousorder - file 20161206_85c293906f1b1c05ed0539a0ef32646d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "957c701ff8f0cccf7380bc96bc63f9a9d81eda6438eda9ba03fb3c7e6f027b53"

  strings:
    $s1 = "var vCi7 = new Function(\"s\", '{var vLNe1 = new Date();vLNe1[\"setUTCFullYear\"](\"2003\");if (vLNe1.getUTCFullYear().toString(" ascii
    $s2 = "var vCi7 = new Function(\"s\", '{var vLNe1 = new Date();vLNe1[\"setUTCFullYear\"](\"2003\");if (vLNe1.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vJz4 = s.split(\"##\"); return vJz4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vPMz8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}