rule sig_20161207_4c9f83f243cd50e4783e65bf20a6b446 {
  meta:
    description = "datamaliciousorder - file 20161207_4c9f83f243cd50e4783e65bf20a6b446.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bcecd8bcc38fe519f4dbf940d70dd493aac65ab7b4072b0fc6104c8e1285fa6"

  strings:
    $s1 = "var vWJk5 = new Function(\"vGWu8\", '{var vHt5 = new Date();vHt5[\"setUTCFullYear\"](\"2003\");if (vHt5.getUTCFullYear().toStrin" ascii
    $s2 = "var vWJk5 = new Function(\"vGWu8\", '{var vHt5 = new Date();vHt5[\"setUTCFullYear\"](\"2003\");if (vHt5.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vENf0 = vGWu8.split(\"###\"); return vENf0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vQPr4 = new Function(\"vGWu8\", '{return vGWu8.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}