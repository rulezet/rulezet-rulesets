rule sig_20161206_be9b66eecee39ab35e4471dbaa50d51b {
  meta:
    description = "datamaliciousorder - file 20161206_be9b66eecee39ab35e4471dbaa50d51b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e417bc4fb2765ee2d711ee8b78de996d360fbdbd9c013ab617c60a0aa5a6c58d"

  strings:
    $s1 = "var vRAx7 = new Function(\"s\", '{var vMWw3 = new Date();vMWw3[\"setUTCFullYear\"](\"2003\");if (vMWw3.getUTCFullYear().toString" ascii
    $s2 = "var vRAx7 = new Function(\"s\", '{var vMWw3 = new Date();vMWw3[\"setUTCFullYear\"](\"2003\");if (vMWw3.getUTCFullYear().toString" ascii
    $s3 = "function vRKc6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vRu3 = s.split(\"##\"); return vRu3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}