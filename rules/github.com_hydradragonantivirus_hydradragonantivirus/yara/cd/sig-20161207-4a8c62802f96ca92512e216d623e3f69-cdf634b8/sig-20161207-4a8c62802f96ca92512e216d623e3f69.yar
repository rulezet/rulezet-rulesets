rule sig_20161207_4a8c62802f96ca92512e216d623e3f69 {
  meta:
    description = "datamaliciousorder - file 20161207_4a8c62802f96ca92512e216d623e3f69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d98ec6af7c28c2f43c1287db095ed7921c5148969b1698f515b17791748f499"

  strings:
    $s1 = "var vGq7 = new Function(\"vWDv4\", '{var vLu2 = new Date();vLu2[\"setUTCFullYear\"](\"2003\");if (vLu2.getUTCFullYear().toString" ascii
    $s2 = "var vGq7 = new Function(\"vWDv4\", '{var vLu2 = new Date();vLu2[\"setUTCFullYear\"](\"2003\");if (vLu2.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vCGk8 = vWDv4.split(\"###\"); return vCGk8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vCp1 = new Function(\"vWDv4\", '{return vWDv4.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}