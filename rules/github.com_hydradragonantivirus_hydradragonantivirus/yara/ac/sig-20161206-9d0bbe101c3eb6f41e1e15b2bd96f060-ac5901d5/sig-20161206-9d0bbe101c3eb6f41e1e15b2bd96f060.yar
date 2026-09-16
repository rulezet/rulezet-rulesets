rule sig_20161206_9d0bbe101c3eb6f41e1e15b2bd96f060 {
  meta:
    description = "datamaliciousorder - file 20161206_9d0bbe101c3eb6f41e1e15b2bd96f060.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bed74d92f68b6499fbef9bef0ee9087e81f93c1d17abf2c6f298f11c7fa4231"

  strings:
    $s1 = "var vFu0 = new Function(\"s\", '{var vGRl6 = new Date();vGRl6[\"setUTCFullYear\"](\"2003\");if (vGRl6.getUTCFullYear().toString(" ascii
    $s2 = "var vFu0 = new Function(\"s\", '{var vGRl6 = new Date();vGRl6[\"setUTCFullYear\"](\"2003\");if (vGRl6.getUTCFullYear().toString(" ascii
    $s3 = "function vFo5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vIp5 = s.split(\"##\"); return vIp5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}