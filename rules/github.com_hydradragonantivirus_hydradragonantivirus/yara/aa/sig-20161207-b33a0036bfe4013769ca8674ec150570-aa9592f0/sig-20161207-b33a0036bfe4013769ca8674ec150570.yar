rule sig_20161207_b33a0036bfe4013769ca8674ec150570 {
  meta:
    description = "datamaliciousorder - file 20161207_b33a0036bfe4013769ca8674ec150570.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289c06d1d9ad44ca1b3cec4aecbac3726b59aa6758742762bdc799956e6240ba"

  strings:
    $s1 = "var vQc4 = new Function(\"vHPa4\", '{var vAQk9 = new Date();vAQk9[\"setUTCFullYear\"](\"2003\");if (vAQk9.getUTCFullYear().toStr" ascii
    $s2 = "var vQc4 = new Function(\"vHPa4\", '{var vAQk9 = new Date();vAQk9[\"setUTCFullYear\"](\"2003\");if (vAQk9.getUTCFullYear().toStr" ascii
    $s3 = "var vAGi9 = new Function(\"vHPa4\", '{return vHPa4.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vTCb4 = vHPa4.split(\"###\"); return vTCb4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}