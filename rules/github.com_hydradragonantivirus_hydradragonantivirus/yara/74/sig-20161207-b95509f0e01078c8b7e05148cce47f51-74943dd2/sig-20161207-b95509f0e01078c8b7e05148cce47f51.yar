rule sig_20161207_b95509f0e01078c8b7e05148cce47f51 {
  meta:
    description = "datamaliciousorder - file 20161207_b95509f0e01078c8b7e05148cce47f51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48b784539b107ac1692ce9b736a7633fea2a8b62e390e888f84f04f6ee6c7962"

  strings:
    $s1 = "var vBx4 = new Function(\"vCMq2\", '{var vFPk0 = new Date();vFPk0[\"setUTCFullYear\"](\"2003\");if (vFPk0.getUTCFullYear().toStr" ascii
    $s2 = "var vBx4 = new Function(\"vCMq2\", '{var vFPk0 = new Date();vFPk0[\"setUTCFullYear\"](\"2003\");if (vFPk0.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vPy9 = vCMq2.split(\"###\"); return vPy9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vSEi1 = new Function(\"vCMq2\", '{return vCMq2.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}