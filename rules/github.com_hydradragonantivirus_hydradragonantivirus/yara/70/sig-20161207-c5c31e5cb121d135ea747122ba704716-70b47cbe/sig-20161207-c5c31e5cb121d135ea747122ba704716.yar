rule sig_20161207_c5c31e5cb121d135ea747122ba704716 {
  meta:
    description = "datamaliciousorder - file 20161207_c5c31e5cb121d135ea747122ba704716.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad32bf47ff83e0f89de49c6acecd93de86279ba55ebaa9b5babad0380ce74101"

  strings:
    $s1 = "var vSOb2 = new Function(\"vSXi6\", '{var vBo1 = new Date();vBo1[\"setUTCFullYear\"](\"2003\");if (vBo1.getUTCFullYear().toStrin" ascii
    $s2 = "var vSOb2 = new Function(\"vSXi6\", '{var vBo1 = new Date();vBo1[\"setUTCFullYear\"](\"2003\");if (vBo1.getUTCFullYear().toStrin" ascii
    $s3 = "var vEm3 = new Function(\"vSXi6\", '{return vSXi6.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vWEk8 = vSXi6.split(\"###\"); return vWEk8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}