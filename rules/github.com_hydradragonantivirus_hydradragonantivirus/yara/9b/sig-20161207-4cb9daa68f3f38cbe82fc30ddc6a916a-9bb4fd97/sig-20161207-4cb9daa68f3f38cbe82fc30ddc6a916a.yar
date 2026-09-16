rule sig_20161207_4cb9daa68f3f38cbe82fc30ddc6a916a {
  meta:
    description = "datamaliciousorder - file 20161207_4cb9daa68f3f38cbe82fc30ddc6a916a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e312afc3a9a675ff641a34840e7cd6a34287c50270b5f728a61cc9569f90130"

  strings:
    $s1 = "var vZIi6 = new Function(\"vGs3\", '{var vXm9 = new Date();vXm9[\"setUTCFullYear\"](\"2003\");if (vXm9.getUTCFullYear().toString" ascii
    $s2 = "var vZIi6 = new Function(\"vGs3\", '{var vXm9 = new Date();vXm9[\"setUTCFullYear\"](\"2003\");if (vXm9.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vOe2 = vGs3.split(\"###\"); return vOe2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vGEl2 = new Function(\"vGs3\", '{return vGs3.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}