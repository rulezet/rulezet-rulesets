rule sig_20161207_55aabb5582866ed8b334fcd4b8d7c976 {
  meta:
    description = "datamaliciousorder - file 20161207_55aabb5582866ed8b334fcd4b8d7c976.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6ee253a7b9c1dedde02c1c53a24ab469284ba444dd48822ae34b6828a95309b"

  strings:
    $s1 = "var vBUx2 = new Function(\"vMp5\", '{var vTg0 = new Date();vTg0[\"setUTCFullYear\"](\"2003\");if (vTg0.getUTCFullYear().toString" ascii
    $s2 = "var vBUx2 = new Function(\"vMp5\", '{var vTg0 = new Date();vTg0[\"setUTCFullYear\"](\"2003\");if (vTg0.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vYo9 = vMp5.split(\"###\"); return vYo9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vYDb4 = new Function(\"vMp5\", '{return vMp5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}