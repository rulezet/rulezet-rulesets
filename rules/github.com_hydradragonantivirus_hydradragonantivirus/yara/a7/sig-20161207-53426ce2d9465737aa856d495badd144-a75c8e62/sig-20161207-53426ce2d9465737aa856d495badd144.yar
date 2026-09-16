rule sig_20161207_53426ce2d9465737aa856d495badd144 {
  meta:
    description = "datamaliciousorder - file 20161207_53426ce2d9465737aa856d495badd144.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f67d9fca54c2473fe6c675f3a3f422cfc85c03d7e6bdcc3e55b33b42172e090"

  strings:
    $s1 = "var vEAc9 = new Function(\"vJo9\", '{var vLIm4 = new Date();vLIm4[\"setUTCFullYear\"](\"2003\");if (vLIm4.getUTCFullYear().toStr" ascii
    $s2 = "var vEAc9 = new Function(\"vJo9\", '{var vLIm4 = new Date();vLIm4[\"setUTCFullYear\"](\"2003\");if (vLIm4.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vJs5 = vJo9.split(\"###\"); return vJs5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vSg3 = new Function(\"vJo9\", '{return vJo9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}