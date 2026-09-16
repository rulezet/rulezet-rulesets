rule sig_20161206_2511c2589187bf91ef3543d18f03e54d {
  meta:
    description = "datamaliciousorder - file 20161206_2511c2589187bf91ef3543d18f03e54d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e0815a55b237f66380be21838db1dac7a193e735167d2289cc5037d641d2eb2"

  strings:
    $s1 = "var vYYy3 = new Function(\"s\", '{var vTVy9 = new Date();vTVy9[\"setUTCFullYear\"](\"2003\");if (vTVy9.getUTCFullYear().toString" ascii
    $s2 = "var vYYy3 = new Function(\"s\", '{var vTVy9 = new Date();vTVy9[\"setUTCFullYear\"](\"2003\");if (vTVy9.getUTCFullYear().toString" ascii
    $s3 = "function vMx0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vFOu0 = s.split(\"##\"); return vFOu0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}