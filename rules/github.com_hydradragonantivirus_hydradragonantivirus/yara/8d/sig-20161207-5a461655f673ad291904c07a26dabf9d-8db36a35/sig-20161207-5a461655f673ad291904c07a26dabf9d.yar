rule sig_20161207_5a461655f673ad291904c07a26dabf9d {
  meta:
    description = "datamaliciousorder - file 20161207_5a461655f673ad291904c07a26dabf9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e951ddb8acb7e755a8074422195c1e35523b801a83795ca4868fee493e5ae211"

  strings:
    $s1 = "var vHOv5 = new Function(\"vYLs5\", '{var vTa2 = new Date();vTa2[\"setUTCFullYear\"](\"2003\");if (vTa2.getUTCFullYear().toStrin" ascii
    $s2 = "var vHOv5 = new Function(\"vYLs5\", '{var vTa2 = new Date();vTa2[\"setUTCFullYear\"](\"2003\");if (vTa2.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vLe2 = vYLs5.split(\"###\"); return vLe2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vKp0 = new Function(\"vYLs5\", '{return vYLs5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}