rule sig_20161206_ac9368a0fa37c48884e9b71b2b51dfdb {
  meta:
    description = "datamaliciousorder - file 20161206_ac9368a0fa37c48884e9b71b2b51dfdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14cfdc798472e0194488eb56bf9cc3dea4db653e3b0284f497a811928bbb7e26"

  strings:
    $s1 = "var vZPq6 = new Function(\"s\", '{var vJId6 = new Date();vJId6[\"setUTCFullYear\"](\"2003\");if (vJId6.getUTCFullYear().toString" ascii
    $s2 = "var vZPq6 = new Function(\"s\", '{var vJId6 = new Date();vJId6[\"setUTCFullYear\"](\"2003\");if (vJId6.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vJMa7 = s.split(\"##\"); return vJMa7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vBOd9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}