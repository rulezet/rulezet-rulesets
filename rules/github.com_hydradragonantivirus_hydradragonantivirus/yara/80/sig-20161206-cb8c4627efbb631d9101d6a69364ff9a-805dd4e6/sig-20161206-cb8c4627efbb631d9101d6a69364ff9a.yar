rule sig_20161206_cb8c4627efbb631d9101d6a69364ff9a {
  meta:
    description = "datamaliciousorder - file 20161206_cb8c4627efbb631d9101d6a69364ff9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38b13d17fdb6bb3a32ec16c5355fcb2134e7effa041e65645b607bafc249d5bf"

  strings:
    $s1 = "var vAq3 = new Function(\"s\", '{var vOi9 = new Date();vOi9[\"setUTCFullYear\"](\"2003\");if (vOi9.getUTCFullYear().toString(10)" ascii
    $s2 = "var vAq3 = new Function(\"s\", '{var vOi9 = new Date();vOi9[\"setUTCFullYear\"](\"2003\");if (vOi9.getUTCFullYear().toString(10)" ascii
    $s3 = "function vLRl0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vZTy9 = s.split(\"##\"); return vZTy9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}