rule sig_20161206_2137a05d1a4d0ac2fd77e4bc667451db {
  meta:
    description = "datamaliciousorder - file 20161206_2137a05d1a4d0ac2fd77e4bc667451db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c6610db21b40ea75d01bad6b26dfb0cd5c0eee95153261f79e470cb3e0107fa"

  strings:
    $s1 = "var vNFo2 = new Function(\"s\", '{var vHYt5 = new Date();vHYt5[\"setUTCFullYear\"](\"2003\");if (vHYt5.getUTCFullYear().toString" ascii
    $s2 = "var vNFo2 = new Function(\"s\", '{var vHYt5 = new Date();vHYt5[\"setUTCFullYear\"](\"2003\");if (vHYt5.getUTCFullYear().toString" ascii
    $s3 = "function vLy1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vJq3 = s.split(\"##\"); return vJq3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}