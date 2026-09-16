rule sig_20161207_1b2dbd9214d81f147e4d7be1063bb144 {
  meta:
    description = "datamaliciousorder - file 20161207_1b2dbd9214d81f147e4d7be1063bb144.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea44b9b9766c3bf20d543af6d3c4b1742515ee03485fc88d158e0e89ce20dc8b"

  strings:
    $s1 = "var vYx2 = new Function(\"vYIi4\", '{var vLRl9 = new Date();vLRl9[\"setUTCFullYear\"](\"2003\");if (vLRl9.getUTCFullYear().toStr" ascii
    $s2 = "var vYx2 = new Function(\"vYIi4\", '{var vLRl9 = new Date();vLRl9[\"setUTCFullYear\"](\"2003\");if (vLRl9.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vJn2 = vYIi4.split(\"###\"); return vJn2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vCb5 = new Function(\"vYIi4\", '{return vYIi4.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}