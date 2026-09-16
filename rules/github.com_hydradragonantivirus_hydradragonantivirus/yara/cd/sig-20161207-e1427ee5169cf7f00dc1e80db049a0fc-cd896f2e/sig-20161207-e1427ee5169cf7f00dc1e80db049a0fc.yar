rule sig_20161207_e1427ee5169cf7f00dc1e80db049a0fc {
  meta:
    description = "datamaliciousorder - file 20161207_e1427ee5169cf7f00dc1e80db049a0fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e7b330dcac5e6e4b5fdc493d54985a84e0ef18de951617c38f5af7ba3ab2d18"

  strings:
    $s1 = "var vRi1 = new Function(\"vJp6\", '{var vGm3 = new Date();vGm3[\"setUTCFullYear\"](\"2003\");if (vGm3.getUTCFullYear().toString(" ascii
    $s2 = "var vRi1 = new Function(\"vJp6\", '{var vGm3 = new Date();vGm3[\"setUTCFullYear\"](\"2003\");if (vGm3.getUTCFullYear().toString(" ascii
    $s3 = "var vYQn4 = new Function(\"vJp6\", '{return vJp6.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vOq8 = vJp6.split(\"###\"); return vOq8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}