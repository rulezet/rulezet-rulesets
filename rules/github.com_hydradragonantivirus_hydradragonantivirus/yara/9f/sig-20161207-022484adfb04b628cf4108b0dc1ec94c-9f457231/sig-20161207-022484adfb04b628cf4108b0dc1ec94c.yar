rule sig_20161207_022484adfb04b628cf4108b0dc1ec94c {
  meta:
    description = "datamaliciousorder - file 20161207_022484adfb04b628cf4108b0dc1ec94c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6542f2ade5fcc88179822036ebce452a5085cf0dc47f496ec3a65cbc4413f1ce"

  strings:
    $s1 = "var vFk7 = new Function(\"vXj5\", '{var vMo8 = new Date();vMo8[\"setUTCFullYear\"](\"2003\");if (vMo8.getUTCFullYear().toString(" ascii
    $s2 = "var vFk7 = new Function(\"vXj5\", '{var vMo8 = new Date();vMo8[\"setUTCFullYear\"](\"2003\");if (vMo8.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vEl0 = vXj5.split(\"###\"); return vEl0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vYu8 = new Function(\"vXj5\", '{return vXj5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}