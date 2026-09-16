rule sig_20161206_81db3c43e5efed82649e49cc2d006c74 {
  meta:
    description = "datamaliciousorder - file 20161206_81db3c43e5efed82649e49cc2d006c74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "514414ec8c5b60d23f2c63f41c4e0b437021f4ebcbc89bf14f75e593b4c30da8"

  strings:
    $s1 = "var vTj9 = new Function(\"s\", '{var vZs2 = new Date();vZs2[\"setUTCFullYear\"](\"2003\");if (vZs2.getUTCFullYear().toString(10)" ascii
    $s2 = "var vTj9 = new Function(\"s\", '{var vZs2 = new Date();vZs2[\"setUTCFullYear\"](\"2003\");if (vZs2.getUTCFullYear().toString(10)" ascii
    $s3 = "function vNDl6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vDAa7 = s.split(\"##\"); return vDAa7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}