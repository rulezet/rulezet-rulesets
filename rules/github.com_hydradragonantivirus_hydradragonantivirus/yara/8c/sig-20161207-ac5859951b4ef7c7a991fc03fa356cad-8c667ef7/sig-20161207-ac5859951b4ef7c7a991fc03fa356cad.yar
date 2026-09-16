rule sig_20161207_ac5859951b4ef7c7a991fc03fa356cad {
  meta:
    description = "datamaliciousorder - file 20161207_ac5859951b4ef7c7a991fc03fa356cad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80a9fdc060f682687bb2c59e46aecfdfe6e6a3f4b6faf0094e88b879f3f32b09"

  strings:
    $s1 = "var vOy5 = new Function(\"vNFg2\", '{var vNc0 = new Date();vNc0[\"setUTCFullYear\"](\"2003\");if (vNc0.getUTCFullYear().toString" ascii
    $s2 = "var vOy5 = new Function(\"vNFg2\", '{var vNc0 = new Date();vNc0[\"setUTCFullYear\"](\"2003\");if (vNc0.getUTCFullYear().toString" ascii
    $s3 = "var vXu5 = new Function(\"vNFg2\", '{return vNFg2.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vLm8 = vNFg2.split(\"###\"); return vLm8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}