rule sig_20161206_903f73a34bca0c1f33936f95473153fd {
  meta:
    description = "datamaliciousorder - file 20161206_903f73a34bca0c1f33936f95473153fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3d680775d157c38e9b0fe32acc97df52d9543c78fcb6ea913ffefe776562490"

  strings:
    $s1 = "var vPv2 = new Function(\"s\", '{var vTe8 = new Date();vTe8[\"setUTCFullYear\"](\"2003\");if (vTe8.getUTCFullYear().toString(10)" ascii
    $s2 = "var vPv2 = new Function(\"s\", '{var vTe8 = new Date();vTe8[\"setUTCFullYear\"](\"2003\");if (vTe8.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vFi9 = s.split(\"##\"); return vFi9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vYl6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}