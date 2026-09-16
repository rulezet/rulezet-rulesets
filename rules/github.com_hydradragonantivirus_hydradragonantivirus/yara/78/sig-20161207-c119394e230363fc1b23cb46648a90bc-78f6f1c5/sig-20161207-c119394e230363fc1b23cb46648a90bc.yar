rule sig_20161207_c119394e230363fc1b23cb46648a90bc {
  meta:
    description = "datamaliciousorder - file 20161207_c119394e230363fc1b23cb46648a90bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd863ed54ee3d2fc114f859beb8475f4d064d7e41be91cbf25692068b6298434"

  strings:
    $s1 = "var vHHv8 = new Function(\"vRJw7\", '{var vBUx8 = new Date();vBUx8[\"setUTCFullYear\"](\"2003\");if (vBUx8.getUTCFullYear().toSt" ascii
    $s2 = "var vHHv8 = new Function(\"vRJw7\", '{var vBUx8 = new Date();vBUx8[\"setUTCFullYear\"](\"2003\");if (vBUx8.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vOVq8 = vRJw7.split(\"###\"); return vOVq8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vXQa0 = new Function(\"vRJw7\", '{return vRJw7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}