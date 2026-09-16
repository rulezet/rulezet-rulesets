rule sig_20161207_3cc2cdd77819ff8b3677367a72d59030 {
  meta:
    description = "datamaliciousorder - file 20161207_3cc2cdd77819ff8b3677367a72d59030.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77856a26613388f225a0d1b9b78bc5bf2909518d6c23c4a2e788068f189e1661"

  strings:
    $s1 = "var vRx4 = new Function(\"vPo4\", '{var vNZo4 = new Date();vNZo4[\"setUTCFullYear\"](\"2003\");if (vNZo4.getUTCFullYear().toStri" ascii
    $s2 = "var vRx4 = new Function(\"vPo4\", '{var vNZo4 = new Date();vNZo4[\"setUTCFullYear\"](\"2003\");if (vNZo4.getUTCFullYear().toStri" ascii
    $s3 = " == \"2003\") {var vDu2 = vPo4.split(\"###\"); return vDu2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vTVa8 = new Function(\"vPo4\", '{return vPo4.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}