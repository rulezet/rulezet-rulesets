rule sig_20161207_90184ac15ebce2a80849747ecdff6c30 {
  meta:
    description = "datamaliciousorder - file 20161207_90184ac15ebce2a80849747ecdff6c30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "856b50de5eeed13b6dff0d3b1c69a4d045799b07ce40dc4b903634595bc4be53"

  strings:
    $s1 = "var vQl0 = new Function(\"vCm9\", '{var vBRx1 = new Date();vBRx1[\"setUTCFullYear\"](\"2003\");if (vBRx1.getUTCFullYear().toStri" ascii
    $s2 = "var vQl0 = new Function(\"vCm9\", '{var vBRx1 = new Date();vBRx1[\"setUTCFullYear\"](\"2003\");if (vBRx1.getUTCFullYear().toStri" ascii
    $s3 = "var vUn7 = new Function(\"vCm9\", '{return vCm9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vHo6 = vCm9.split(\"###\"); return vHo6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}