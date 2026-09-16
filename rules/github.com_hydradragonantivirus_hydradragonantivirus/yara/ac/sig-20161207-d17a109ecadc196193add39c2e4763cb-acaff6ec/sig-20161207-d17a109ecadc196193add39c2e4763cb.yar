rule sig_20161207_d17a109ecadc196193add39c2e4763cb {
  meta:
    description = "datamaliciousorder - file 20161207_d17a109ecadc196193add39c2e4763cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "609dea3488d2bd098e807c61158311488abf022003bf29367b4605b5cc3eb4ca"

  strings:
    $s1 = "var vRBc7 = new Function(\"vDk9\", '{var vDn9 = new Date();vDn9[\"setUTCFullYear\"](\"2003\");if (vDn9.getUTCFullYear().toString" ascii
    $s2 = "var vRBc7 = new Function(\"vDk9\", '{var vDn9 = new Date();vDn9[\"setUTCFullYear\"](\"2003\");if (vDn9.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vYo5 = vDk9.split(\"###\"); return vYo5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vOIs6 = new Function(\"vDk9\", '{return vDk9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}