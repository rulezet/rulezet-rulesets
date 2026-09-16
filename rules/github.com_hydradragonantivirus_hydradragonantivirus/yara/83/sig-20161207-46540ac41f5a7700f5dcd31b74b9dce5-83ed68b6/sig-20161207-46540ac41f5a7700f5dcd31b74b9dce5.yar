rule sig_20161207_46540ac41f5a7700f5dcd31b74b9dce5 {
  meta:
    description = "datamaliciousorder - file 20161207_46540ac41f5a7700f5dcd31b74b9dce5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98229775ac80837e8024c883b48609cb04c25bcbcb5ac7c9fd2ec2e8c7c3c819"

  strings:
    $s1 = "var vVe6 = new Function(\"vOp7\", '{var vKh7 = new Date();vKh7[\"setUTCFullYear\"](\"2003\");if (vKh7.getUTCFullYear().toString(" ascii
    $s2 = "var vVe6 = new Function(\"vOp7\", '{var vKh7 = new Date();vKh7[\"setUTCFullYear\"](\"2003\");if (vKh7.getUTCFullYear().toString(" ascii
    $s3 = "var vXx8 = new Function(\"vOp7\", '{return vOp7.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vMd9 = vOp7.split(\"###\"); return vMd9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}