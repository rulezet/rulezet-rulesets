rule sig_20161206_919e7c7499b51f1fd3ecbc8ee4e2334f {
  meta:
    description = "datamaliciousorder - file 20161206_919e7c7499b51f1fd3ecbc8ee4e2334f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "040baaf795cbc68ca772d13da2d16ba647e282fe95b4e4d4eea00fe042cb27a6"

  strings:
    $s1 = "var vRWq9 = new Function(\"s\", '{var vRa2 = new Date();vRa2[\"setUTCFullYear\"](\"2003\");if (vRa2.getUTCFullYear().toString(10" ascii
    $s2 = "var vRWq9 = new Function(\"s\", '{var vRa2 = new Date();vRa2[\"setUTCFullYear\"](\"2003\");if (vRa2.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vVHh8 = s.split(\"##\"); return vVHh8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vWf8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}