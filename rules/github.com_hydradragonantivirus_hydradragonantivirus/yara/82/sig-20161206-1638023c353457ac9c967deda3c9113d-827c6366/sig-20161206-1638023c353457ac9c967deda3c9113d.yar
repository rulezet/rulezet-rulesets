rule sig_20161206_1638023c353457ac9c967deda3c9113d {
  meta:
    description = "datamaliciousorder - file 20161206_1638023c353457ac9c967deda3c9113d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ebab29c7b2d96e73fc1a0ee1b113fb0677d6816b4e69f65af5d88f11e618d8d"

  strings:
    $s1 = "var vYKk5 = new Function(\"s\", '{var vLx5 = new Date();vLx5[\"setUTCFullYear\"](\"2003\");if (vLx5.getUTCFullYear().toString(10" ascii
    $s2 = "var vYKk5 = new Function(\"s\", '{var vLx5 = new Date();vLx5[\"setUTCFullYear\"](\"2003\");if (vLx5.getUTCFullYear().toString(10" ascii
    $s3 = "function vEw7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vCMw9 = s.split(\"##\"); return vCMw9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}