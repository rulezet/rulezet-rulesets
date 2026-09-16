rule sig_20161207_c0e20cdcbaac978c798da3846385ce40 {
  meta:
    description = "datamaliciousorder - file 20161207_c0e20cdcbaac978c798da3846385ce40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49d33e20c961e38e6c0b488bef69d13d3fd3d4e3053265c2a337f34c0c77773f"

  strings:
    $s1 = "var vSXf0 = new Function(\"vTVw6\", '{var vRLi7 = new Date();vRLi7[\"setUTCFullYear\"](\"2003\");if (vRLi7.getUTCFullYear().toSt" ascii
    $s2 = "var vSXf0 = new Function(\"vTVw6\", '{var vRLi7 = new Date();vRLi7[\"setUTCFullYear\"](\"2003\");if (vRLi7.getUTCFullYear().toSt" ascii
    $s3 = "var vIp7 = new Function(\"vTVw6\", '{return vTVw6.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "0) == \"2003\") {var vATc0 = vTVw6.split(\"###\"); return vATc0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}