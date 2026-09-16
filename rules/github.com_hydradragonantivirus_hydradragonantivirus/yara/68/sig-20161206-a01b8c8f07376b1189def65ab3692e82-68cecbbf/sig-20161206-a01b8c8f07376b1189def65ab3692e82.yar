rule sig_20161206_a01b8c8f07376b1189def65ab3692e82 {
  meta:
    description = "datamaliciousorder - file 20161206_a01b8c8f07376b1189def65ab3692e82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0194907d3e8f6b88511ce0dffa205ff5aca60597f02d1d8e5f7db56c9ad773be"

  strings:
    $s1 = "var vNs0 = new Function(\"s\", '{var vYAp1 = new Date();vYAp1[\"setUTCFullYear\"](\"2003\");if (vYAp1.getUTCFullYear().toString(" ascii
    $s2 = "var vNs0 = new Function(\"s\", '{var vYAp1 = new Date();vYAp1[\"setUTCFullYear\"](\"2003\");if (vYAp1.getUTCFullYear().toString(" ascii
    $s3 = "function vUSp6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vYYf7 = s.split(\"##\"); return vYYf7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}