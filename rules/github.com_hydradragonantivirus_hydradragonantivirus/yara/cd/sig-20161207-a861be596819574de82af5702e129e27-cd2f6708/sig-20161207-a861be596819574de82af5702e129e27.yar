rule sig_20161207_a861be596819574de82af5702e129e27 {
  meta:
    description = "datamaliciousorder - file 20161207_a861be596819574de82af5702e129e27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3573f02584a81c71358345da682f262e50ef8b6350eddbf5c088daa55cfbe340"

  strings:
    $s1 = "var vLl1 = new Function(\"vETc3\", '{var vQUs0 = new Date();vQUs0[\"setUTCFullYear\"](\"2003\");if (vQUs0.getUTCFullYear().toStr" ascii
    $s2 = "var vLl1 = new Function(\"vETc3\", '{var vQUs0 = new Date();vQUs0[\"setUTCFullYear\"](\"2003\");if (vQUs0.getUTCFullYear().toStr" ascii
    $s3 = "var vRTj2 = new Function(\"vETc3\", '{return vETc3.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vZLc3 = vETc3.split(\"###\"); return vZLc3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}