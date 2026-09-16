rule sig_20161207_ba8cef288179133fdfca16d548f904be {
  meta:
    description = "datamaliciousorder - file 20161207_ba8cef288179133fdfca16d548f904be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d8a53ce04662fadd91a65fd46f6b550bf8c36bc3e8532068afe48111e5b3c9f"

  strings:
    $s1 = "var vTUi8 = new Function(\"vUr2\", '{var vZm3 = new Date();vZm3[\"setUTCFullYear\"](\"2003\");if (vZm3.getUTCFullYear().toString" ascii
    $s2 = "var vTUi8 = new Function(\"vUr2\", '{var vZm3 = new Date();vZm3[\"setUTCFullYear\"](\"2003\");if (vZm3.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vDJr6 = vUr2.split(\"###\"); return vDJr6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vBb6 = new Function(\"vUr2\", '{return vUr2.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}