rule sig_20161207_d1186b6f273e59f08ae7eb92f483a7c8 {
  meta:
    description = "datamaliciousorder - file 20161207_d1186b6f273e59f08ae7eb92f483a7c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43a1c27a8a645dfda26139a90d07bacf947fbb7fd1c75522ffe0a6ca302c4c95"

  strings:
    $s1 = "var vZp6 = new Function(\"vVUv9\", '{var vOUs2 = new Date();vOUs2[\"setUTCFullYear\"](\"2003\");if (vOUs2.getUTCFullYear().toStr" ascii
    $s2 = "var vZp6 = new Function(\"vVUv9\", '{var vOUs2 = new Date();vOUs2[\"setUTCFullYear\"](\"2003\");if (vOUs2.getUTCFullYear().toStr" ascii
    $s3 = "var vOGy3 = new Function(\"vVUv9\", '{return vVUv9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vRr5 = vVUv9.split(\"###\"); return vRr5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}