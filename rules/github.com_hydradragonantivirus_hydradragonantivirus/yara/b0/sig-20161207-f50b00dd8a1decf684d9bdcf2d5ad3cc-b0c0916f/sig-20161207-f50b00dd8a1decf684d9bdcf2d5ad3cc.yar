rule sig_20161207_f50b00dd8a1decf684d9bdcf2d5ad3cc {
  meta:
    description = "datamaliciousorder - file 20161207_f50b00dd8a1decf684d9bdcf2d5ad3cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31568e272312afa2e0ba736fb7a19195f69f972f1fcae9d745bde780284e0e0d"

  strings:
    $s1 = "var vQm5 = new Function(\"vKEd2\", '{var vXJb5 = new Date();vXJb5[\"setUTCFullYear\"](\"2003\");if (vXJb5.getUTCFullYear().toStr" ascii
    $s2 = "var vQm5 = new Function(\"vKEd2\", '{var vXJb5 = new Date();vXJb5[\"setUTCFullYear\"](\"2003\");if (vXJb5.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vYg2 = vKEd2.split(\"###\"); return vYg2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vISu9 = new Function(\"vKEd2\", '{return vKEd2.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}