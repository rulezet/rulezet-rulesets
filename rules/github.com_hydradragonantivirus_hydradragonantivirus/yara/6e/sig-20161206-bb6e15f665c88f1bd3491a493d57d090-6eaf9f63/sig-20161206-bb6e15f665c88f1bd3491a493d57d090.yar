rule sig_20161206_bb6e15f665c88f1bd3491a493d57d090 {
  meta:
    description = "datamaliciousorder - file 20161206_bb6e15f665c88f1bd3491a493d57d090.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af5d3313f6facfb9ea896e3c8ce7b9b966d33c0e704365d5f9602e93af8e2ac5"

  strings:
    $s1 = "var vFi1 = new Function(\"s\", '{var vTn2 = new Date();vTn2[\"setUTCFullYear\"](\"2003\");if (vTn2.getUTCFullYear().toString(10)" ascii
    $s2 = "var vFi1 = new Function(\"s\", '{var vTn2 = new Date();vTn2[\"setUTCFullYear\"](\"2003\");if (vTn2.getUTCFullYear().toString(10)" ascii
    $s3 = "function vXQg3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vDRe1 = s.split(\"##\"); return vDRe1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}