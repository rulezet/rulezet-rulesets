rule sig_20161207_00ebb5467f4028023c2a4b28775b4fbf {
  meta:
    description = "datamaliciousorder - file 20161207_00ebb5467f4028023c2a4b28775b4fbf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5db6c2553a8ce9c706af3b1a04cfd6cf2960a93cfc21ba296960d16064d3d15"

  strings:
    $s1 = "var vQl1 = new Function(\"vXa5\", '{var vHWe1 = new Date();vHWe1[\"setUTCFullYear\"](\"2003\");if (vHWe1.getUTCFullYear().toStri" ascii
    $s2 = "var vQl1 = new Function(\"vXa5\", '{var vHWe1 = new Date();vHWe1[\"setUTCFullYear\"](\"2003\");if (vHWe1.getUTCFullYear().toStri" ascii
    $s3 = " == \"2003\") {var vRs5 = vXa5.split(\"###\"); return vRs5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vLLo4 = new Function(\"vXa5\", '{return vXa5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}