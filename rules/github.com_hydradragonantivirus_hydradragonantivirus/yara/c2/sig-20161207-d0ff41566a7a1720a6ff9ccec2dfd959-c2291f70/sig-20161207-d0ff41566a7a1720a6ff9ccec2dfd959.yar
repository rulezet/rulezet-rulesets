rule sig_20161207_d0ff41566a7a1720a6ff9ccec2dfd959 {
  meta:
    description = "datamaliciousorder - file 20161207_d0ff41566a7a1720a6ff9ccec2dfd959.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c25d6c2a057627c0970ce5cb96d94aed390c5c18c80305363f01a0b6e4c4ff27"

  strings:
    $s1 = "var vLt3 = new Function(\"vHIm2\", '{var vDj0 = new Date();vDj0[\"setUTCFullYear\"](\"2003\");if (vDj0.getUTCFullYear().toString" ascii
    $s2 = "var vLt3 = new Function(\"vHIm2\", '{var vDj0 = new Date();vDj0[\"setUTCFullYear\"](\"2003\");if (vDj0.getUTCFullYear().toString" ascii
    $s3 = "var vDz5 = new Function(\"vHIm2\", '{return vHIm2.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vSTx7 = vHIm2.split(\"###\"); return vSTx7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}