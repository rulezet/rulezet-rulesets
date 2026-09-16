rule sig_20161207_eb78a25331b33e63dbd2d328d2fffab7 {
  meta:
    description = "datamaliciousorder - file 20161207_eb78a25331b33e63dbd2d328d2fffab7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "175ffb6580d701f2dcd8735433eafd6dab17e52c1ed7ed24f97581465c875c90"

  strings:
    $s1 = "var vODp0 = new Function(\"vMVa1\", '{var vNi4 = new Date();vNi4[\"setUTCFullYear\"](\"2003\");if (vNi4.getUTCFullYear().toStrin" ascii
    $s2 = "var vODp0 = new Function(\"vMVa1\", '{var vNi4 = new Date();vNi4[\"setUTCFullYear\"](\"2003\");if (vNi4.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vSd9 = vMVa1.split(\"###\"); return vSd9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vFp4 = new Function(\"vMVa1\", '{return vMVa1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}