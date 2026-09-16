rule sig_20161206_cec6c1557d52bfca76b3d239df0ba026 {
  meta:
    description = "datamaliciousorder - file 20161206_cec6c1557d52bfca76b3d239df0ba026.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41194f3f21460923d292118d545375171a94e84840c85923daa221f4e8c93153"

  strings:
    $s1 = "var vBWr9 = new Function(\"s\", '{var vVDw1 = new Date();vVDw1[\"setUTCFullYear\"](\"2003\");if (vVDw1.getUTCFullYear().toString" ascii
    $s2 = "var vBWr9 = new Function(\"s\", '{var vVDw1 = new Date();vVDw1[\"setUTCFullYear\"](\"2003\");if (vVDw1.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vLg6 = s.split(\"##\"); return vLg6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vOg4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}