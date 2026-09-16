rule sig_20161206_1fe1cdd149806e19e43460ee198a945a {
  meta:
    description = "datamaliciousorder - file 20161206_1fe1cdd149806e19e43460ee198a945a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e83af09538035096506b9f8ee8033c7fd2f712d2dc28fdb5dc481eb7d3fd2788"

  strings:
    $s1 = "var vSPt5 = new Function(\"s\", '{var vIAz6 = new Date();vIAz6[\"setUTCFullYear\"](\"2003\");if (vIAz6.getUTCFullYear().toString" ascii
    $s2 = "var vSPt5 = new Function(\"s\", '{var vIAz6 = new Date();vIAz6[\"setUTCFullYear\"](\"2003\");if (vIAz6.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vJc8 = s.split(\"##\"); return vJc8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vXXg2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}