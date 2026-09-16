rule sig_20161207_e961ec2c83ce714cc2526315cda48621 {
  meta:
    description = "datamaliciousorder - file 20161207_e961ec2c83ce714cc2526315cda48621.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3df462bcdc6d939d46ff4d881ce9944d972170a248cc9d5fa22ecd3d8a909966"

  strings:
    $s1 = "var vPMd0 = new Function(\"vNe0\", '{var vGSx9 = new Date();vGSx9[\"setUTCFullYear\"](\"2003\");if (vGSx9.getUTCFullYear().toStr" ascii
    $s2 = "var vPMd0 = new Function(\"vNe0\", '{var vGSx9 = new Date();vGSx9[\"setUTCFullYear\"](\"2003\");if (vGSx9.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vPi7 = vNe0.split(\"###\"); return vPi7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vLKf6 = new Function(\"vNe0\", '{return vNe0.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}