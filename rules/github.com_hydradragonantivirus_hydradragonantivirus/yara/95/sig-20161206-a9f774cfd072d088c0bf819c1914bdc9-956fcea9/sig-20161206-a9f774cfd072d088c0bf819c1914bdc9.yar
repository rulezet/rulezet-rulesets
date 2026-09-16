rule sig_20161206_a9f774cfd072d088c0bf819c1914bdc9 {
  meta:
    description = "datamaliciousorder - file 20161206_a9f774cfd072d088c0bf819c1914bdc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff956bab96e4c1b2fc1adbb1acd908f0d0a656f52e083bd870a48f17246573f4"

  strings:
    $s1 = "var vZx5 = new Function(\"s\", '{var vKMg6 = new Date();vKMg6[\"setUTCFullYear\"](\"2003\");if (vKMg6.getUTCFullYear().toString(" ascii
    $s2 = "var vZx5 = new Function(\"s\", '{var vKMg6 = new Date();vKMg6[\"setUTCFullYear\"](\"2003\");if (vKMg6.getUTCFullYear().toString(" ascii
    $s3 = "function vUCx4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vJo5 = s.split(\"##\"); return vJo5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}