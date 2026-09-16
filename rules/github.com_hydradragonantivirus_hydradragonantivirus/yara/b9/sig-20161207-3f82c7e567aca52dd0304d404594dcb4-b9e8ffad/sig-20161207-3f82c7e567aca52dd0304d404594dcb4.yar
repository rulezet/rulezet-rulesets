rule sig_20161207_3f82c7e567aca52dd0304d404594dcb4 {
  meta:
    description = "datamaliciousorder - file 20161207_3f82c7e567aca52dd0304d404594dcb4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "751cd24df7c527cfa30a990ad1604de05c60ec40b148fabc9384294337271019"

  strings:
    $s1 = "var vFa8 = new Function(\"vFq4\", '{var vCUd5 = new Date();vCUd5[\"setUTCFullYear\"](\"2003\");if (vCUd5.getUTCFullYear().toStri" ascii
    $s2 = "var vFa8 = new Function(\"vFq4\", '{var vCUd5 = new Date();vCUd5[\"setUTCFullYear\"](\"2003\");if (vCUd5.getUTCFullYear().toStri" ascii
    $s3 = " == \"2003\") {var vSMj7 = vFq4.split(\"###\"); return vSMj7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vORr1 = new Function(\"vFq4\", '{return vFq4.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}