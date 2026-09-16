rule sig_20161207_1ef7c42513223215220dcceba46289a4 {
  meta:
    description = "datamaliciousorder - file 20161207_1ef7c42513223215220dcceba46289a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93cbd59dc4f8df7102b000c8cc1f9777dd0c8c8526fee48f8185cb5b6739b87c"

  strings:
    $s1 = "var vMu4 = new Function(\"vLGl6\", '{var vVt1 = new Date();vVt1[\"setUTCFullYear\"](\"2003\");if (vVt1.getUTCFullYear().toString" ascii
    $s2 = "var vMu4 = new Function(\"vLGl6\", '{var vVt1 = new Date();vVt1[\"setUTCFullYear\"](\"2003\");if (vVt1.getUTCFullYear().toString" ascii
    $s3 = "var vKHg3 = new Function(\"vLGl6\", '{return vLGl6.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vDs1 = vLGl6.split(\"###\"); return vDs1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}