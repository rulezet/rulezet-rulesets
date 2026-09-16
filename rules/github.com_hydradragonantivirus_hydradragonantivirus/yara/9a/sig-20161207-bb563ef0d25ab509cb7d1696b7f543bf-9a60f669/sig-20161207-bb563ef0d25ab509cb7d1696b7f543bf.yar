rule sig_20161207_bb563ef0d25ab509cb7d1696b7f543bf {
  meta:
    description = "datamaliciousorder - file 20161207_bb563ef0d25ab509cb7d1696b7f543bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17d540a71b860a394ae7aec40739469cb441fe2eb816ef3c819abcb3d7f12552"

  strings:
    $s1 = "var vYi6 = new Function(\"vGt2\", '{var vSHf2 = new Date();vSHf2[\"setUTCFullYear\"](\"2003\");if (vSHf2.getUTCFullYear().toStri" ascii
    $s2 = "var vYi6 = new Function(\"vGt2\", '{var vSHf2 = new Date();vSHf2[\"setUTCFullYear\"](\"2003\");if (vSHf2.getUTCFullYear().toStri" ascii
    $s3 = "var vAJc3 = new Function(\"vGt2\", '{return vGt2.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vId6 = vGt2.split(\"###\"); return vId6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}