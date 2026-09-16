rule sig_20161206_a41b19b8755b06a0901fdbf7095b02db {
  meta:
    description = "datamaliciousorder - file 20161206_a41b19b8755b06a0901fdbf7095b02db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "295ae4f594491523ba1c7e537c75da2e14fdaaa1851ac86b9abe58ef6770e883"

  strings:
    $s1 = "var vCYc4 = new Function(\"s\", '{var vLZz2 = new Date();vLZz2[\"setUTCFullYear\"](\"2003\");if (vLZz2.getUTCFullYear().toString" ascii
    $s2 = "var vCYc4 = new Function(\"s\", '{var vLZz2 = new Date();vLZz2[\"setUTCFullYear\"](\"2003\");if (vLZz2.getUTCFullYear().toString" ascii
    $s3 = "function vBTk7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vTg2 = s.split(\"##\"); return vTg2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}