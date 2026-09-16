rule sig_20161207_e6b9702d9718e88ecae67bf71e133f43 {
  meta:
    description = "datamaliciousorder - file 20161207_e6b9702d9718e88ecae67bf71e133f43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c969d61a8c6a61902a8dd6f45a21f75961a8457a70fcdf771277455eb98e1b7"

  strings:
    $s1 = "var vVu8 = new Function(\"vPEk3\", '{var vLw9 = new Date();vLw9[\"setUTCFullYear\"](\"2003\");if (vLw9.getUTCFullYear().toString" ascii
    $s2 = "var vVu8 = new Function(\"vPEk3\", '{var vLw9 = new Date();vLw9[\"setUTCFullYear\"](\"2003\");if (vLw9.getUTCFullYear().toString" ascii
    $s3 = "var vUDi3 = new Function(\"vPEk3\", '{return vPEk3.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vAVp7 = vPEk3.split(\"###\"); return vAVp7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}