rule sig_20161206_7c2ce453e61eecdb86ba5f3e3d3b3a1c {
  meta:
    description = "datamaliciousorder - file 20161206_7c2ce453e61eecdb86ba5f3e3d3b3a1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77679a2b287a66ac4980f5142663086606d9946c0d2096dfb160511a9dd1f1b3"

  strings:
    $s1 = "var vGBr8 = new Function(\"s\", '{var vHl8 = new Date();vHl8[\"setUTCFullYear\"](\"2003\");if (vHl8.getUTCFullYear().toString(10" ascii
    $s2 = "var vGBr8 = new Function(\"s\", '{var vHl8 = new Date();vHl8[\"setUTCFullYear\"](\"2003\");if (vHl8.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vUw4 = s.split(\"##\"); return vUw4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vJYk1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}