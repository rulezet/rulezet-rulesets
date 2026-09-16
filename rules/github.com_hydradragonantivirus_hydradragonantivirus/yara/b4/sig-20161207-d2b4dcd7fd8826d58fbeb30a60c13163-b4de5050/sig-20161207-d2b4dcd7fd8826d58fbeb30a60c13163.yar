rule sig_20161207_d2b4dcd7fd8826d58fbeb30a60c13163 {
  meta:
    description = "datamaliciousorder - file 20161207_d2b4dcd7fd8826d58fbeb30a60c13163.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e3b6f111c6d09be8b1647a3d1a79f7bab5d9d8f856ec7f42bd09c61dd2f7d4e"

  strings:
    $s1 = "var vZVw7 = new Function(\"vHWu9\", '{var vMl0 = new Date();vMl0[\"setUTCFullYear\"](\"2003\");if (vMl0.getUTCFullYear().toStrin" ascii
    $s2 = "var vZVw7 = new Function(\"vHWu9\", '{var vMl0 = new Date();vMl0[\"setUTCFullYear\"](\"2003\");if (vMl0.getUTCFullYear().toStrin" ascii
    $s3 = "var vONx7 = new Function(\"vHWu9\", '{return vHWu9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vYc3 = vHWu9.split(\"###\"); return vYc3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}