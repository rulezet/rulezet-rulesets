rule sig_20161206_a69d2664f1e5a541bfecfe43942ab8e6 {
  meta:
    description = "datamaliciousorder - file 20161206_a69d2664f1e5a541bfecfe43942ab8e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "093780522e0da1d96b935f9d5da77bd391322dc0cb210fe6c7c4ff47d5beafcd"

  strings:
    $s1 = "var vYJy1 = new Function(\"s\", '{var vBUf8 = new Date();vBUf8[\"setUTCFullYear\"](\"2003\");if (vBUf8.getUTCFullYear().toString" ascii
    $s2 = "var vYJy1 = new Function(\"s\", '{var vBUf8 = new Date();vBUf8[\"setUTCFullYear\"](\"2003\");if (vBUf8.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vUc7 = s.split(\"##\"); return vUc7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vWc1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}