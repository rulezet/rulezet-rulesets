rule sig_20161206_c0b833044a1e1dbf925536e8e9663bb0 {
  meta:
    description = "datamaliciousorder - file 20161206_c0b833044a1e1dbf925536e8e9663bb0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dd71bcfa3e2d988a7ec5f7f6769a29a9cfaac2c75b88598a080c361f21b30e4"

  strings:
    $s1 = "var vFl6 = new Function(\"s\", '{var vXp1 = new Date();vXp1[\"setUTCFullYear\"](\"2003\");if (vXp1.getUTCFullYear().toString(10)" ascii
    $s2 = "var vFl6 = new Function(\"s\", '{var vXp1 = new Date();vXp1[\"setUTCFullYear\"](\"2003\");if (vXp1.getUTCFullYear().toString(10)" ascii
    $s3 = "function vVe6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vFKv0 = s.split(\"##\"); return vFKv0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}