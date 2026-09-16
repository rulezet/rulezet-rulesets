rule sig_20161207_f7d524feb5222cfa148b39906274b627 {
  meta:
    description = "datamaliciousorder - file 20161207_f7d524feb5222cfa148b39906274b627.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d068dd6289e0dc3c7c52a4887079d54e68dfd6559beb8e6f69f13c6706c368a"

  strings:
    $s1 = "var vWWp8 = new Function(\"vTa2\", '{var vXw3 = new Date();vXw3[\"setUTCFullYear\"](\"2003\");if (vXw3.getUTCFullYear().toString" ascii
    $s2 = "var vWWp8 = new Function(\"vTa2\", '{var vXw3 = new Date();vXw3[\"setUTCFullYear\"](\"2003\");if (vXw3.getUTCFullYear().toString" ascii
    $s3 = "var vYa9 = new Function(\"vTa2\", '{return vTa2.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vTo1 = vTa2.split(\"###\"); return vTo1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}