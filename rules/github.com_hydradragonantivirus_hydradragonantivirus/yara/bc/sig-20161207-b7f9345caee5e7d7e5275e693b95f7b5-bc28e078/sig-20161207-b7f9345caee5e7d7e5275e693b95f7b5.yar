rule sig_20161207_b7f9345caee5e7d7e5275e693b95f7b5 {
  meta:
    description = "datamaliciousorder - file 20161207_b7f9345caee5e7d7e5275e693b95f7b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00b2d0bfe2a8e9ea0df7ae988e29c2634264342f4dfbc7e5e851a6b9c2787814"

  strings:
    $s1 = "var vEh4 = new Function(\"vOp7\", '{var vDFt5 = new Date();vDFt5[\"setUTCFullYear\"](\"2003\");if (vDFt5.getUTCFullYear().toStri" ascii
    $s2 = "var vEh4 = new Function(\"vOp7\", '{var vDFt5 = new Date();vDFt5[\"setUTCFullYear\"](\"2003\");if (vDFt5.getUTCFullYear().toStri" ascii
    $s3 = " == \"2003\") {var vQQl5 = vOp7.split(\"###\"); return vQQl5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vRx6 = new Function(\"vOp7\", '{return vOp7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}