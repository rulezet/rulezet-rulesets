rule sig_20161206_da424cd5acba2e540e43d8a55d9c03e0 {
  meta:
    description = "datamaliciousorder - file 20161206_da424cd5acba2e540e43d8a55d9c03e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5627bcff9126e29522bbb3d94c535e00327b68928466bd69c62b90947a34497"

  strings:
    $s1 = "var vTJz0 = new Function(\"s\", '{var vQi1 = new Date();vQi1[\"setUTCFullYear\"](\"2003\");if (vQi1.getUTCFullYear().toString(10" ascii
    $s2 = "var vTJz0 = new Function(\"s\", '{var vQi1 = new Date();vQi1[\"setUTCFullYear\"](\"2003\");if (vQi1.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vEq0 = s.split(\"##\"); return vEq0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vBGx5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}