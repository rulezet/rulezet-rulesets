rule sig_20161206_5b603d80a4f27e4c1fa56ef992a22d4a {
  meta:
    description = "datamaliciousorder - file 20161206_5b603d80a4f27e4c1fa56ef992a22d4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a5677ba24470221a5d8dc4bc32908893d3c165c20489afdd8d71ff1fd1cbb08"

  strings:
    $s1 = "var vMNy1 = new Function(\"s\", '{var vQv5 = new Date();vQv5[\"setUTCFullYear\"](\"2003\");if (vQv5.getUTCFullYear().toString(10" ascii
    $s2 = "var vMNy1 = new Function(\"s\", '{var vQv5 = new Date();vQv5[\"setUTCFullYear\"](\"2003\");if (vQv5.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vYv8 = s.split(\"##\"); return vYv8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vAy5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}