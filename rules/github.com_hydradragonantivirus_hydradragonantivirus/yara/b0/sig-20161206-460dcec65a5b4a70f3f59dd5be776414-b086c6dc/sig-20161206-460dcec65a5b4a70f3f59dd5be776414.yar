rule sig_20161206_460dcec65a5b4a70f3f59dd5be776414 {
  meta:
    description = "datamaliciousorder - file 20161206_460dcec65a5b4a70f3f59dd5be776414.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95f3499b6be00c15d1a4aa81667b7023eed3c295c3e18d63a27effaaf766f8dc"

  strings:
    $s1 = "var vIWi6 = new Function(\"s\", '{var vRGq6 = new Date();vRGq6[\"setUTCFullYear\"](\"2003\");if (vRGq6.getUTCFullYear().toString" ascii
    $s2 = "var vIWi6 = new Function(\"s\", '{var vRGq6 = new Date();vRGq6[\"setUTCFullYear\"](\"2003\");if (vRGq6.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vISb8 = s.split(\"##\"); return vISb8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vLEs0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}