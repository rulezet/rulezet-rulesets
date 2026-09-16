rule sig_20161207_e18781808a464f39b176292f80e5df9c {
  meta:
    description = "datamaliciousorder - file 20161207_e18781808a464f39b176292f80e5df9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afbed21a0c13a1bfb25f62350d5a36f85376fcc1acaf935540608e6c8e5cfbdc"

  strings:
    $s1 = "var vHKl1 = new Function(\"vZXf9\", '{var vWv9 = new Date();vWv9[\"setUTCFullYear\"](\"2003\");if (vWv9.getUTCFullYear().toStrin" ascii
    $s2 = "var vHKl1 = new Function(\"vZXf9\", '{var vWv9 = new Date();vWv9[\"setUTCFullYear\"](\"2003\");if (vWv9.getUTCFullYear().toStrin" ascii
    $s3 = "var vMXa3 = new Function(\"vZXf9\", '{return vZXf9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vBe6 = vZXf9.split(\"###\"); return vBe6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}