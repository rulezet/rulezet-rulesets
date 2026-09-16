rule sig_20161207_c65a23c20fa2c0d02fe2b32d2de4e66b {
  meta:
    description = "datamaliciousorder - file 20161207_c65a23c20fa2c0d02fe2b32d2de4e66b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e945065d56b404110da74a72ca3c451a68b620f6cbbc6416c13758962d9f36d"

  strings:
    $s1 = "var vXFt7 = new Function(\"vYJc1\", '{var vTHn1 = new Date();vTHn1[\"setUTCFullYear\"](\"2003\");if (vTHn1.getUTCFullYear().toSt" ascii
    $s2 = "var vXFt7 = new Function(\"vYJc1\", '{var vTHn1 = new Date();vTHn1[\"setUTCFullYear\"](\"2003\");if (vTHn1.getUTCFullYear().toSt" ascii
    $s3 = "var vTc9 = new Function(\"vYJc1\", '{return vYJc1.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "0) == \"2003\") {var vFVt7 = vYJc1.split(\"###\"); return vFVt7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}