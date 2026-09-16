rule sig_20161207_2c28fdf53d2659c7b83b40061944be06 {
  meta:
    description = "datamaliciousorder - file 20161207_2c28fdf53d2659c7b83b40061944be06.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eac51b51e7b3d55787fa942a5c205e132bead8215b3b09ef44a071341bc1c8b9"

  strings:
    $s1 = "var vVWy4 = new Function(\"vLZs5\", '{var vRs2 = new Date();vRs2[\"setUTCFullYear\"](\"2003\");if (vRs2.getUTCFullYear().toStrin" ascii
    $s2 = "var vVWy4 = new Function(\"vLZs5\", '{var vRs2 = new Date();vRs2[\"setUTCFullYear\"](\"2003\");if (vRs2.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vHPh5 = vLZs5.split(\"###\"); return vHPh5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vWFc0 = new Function(\"vLZs5\", '{return vLZs5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}