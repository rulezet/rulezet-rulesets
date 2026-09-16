rule sig_20161207_34bcf3f655855aaa4cbdfe60e613f43c {
  meta:
    description = "datamaliciousorder - file 20161207_34bcf3f655855aaa4cbdfe60e613f43c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "041d964eba4f8c543ef278cf202741aec0bd58b1a0e3fad027944d1b27e5ab09"

  strings:
    $s1 = "var vYx0 = new Function(\"vEWv1\", '{var vCZf9 = new Date();vCZf9[\"setUTCFullYear\"](\"2003\");if (vCZf9.getUTCFullYear().toStr" ascii
    $s2 = "var vYx0 = new Function(\"vEWv1\", '{var vCZf9 = new Date();vCZf9[\"setUTCFullYear\"](\"2003\");if (vCZf9.getUTCFullYear().toStr" ascii
    $s3 = "var vFGi8 = new Function(\"vEWv1\", '{return vEWv1.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vPWn4 = vEWv1.split(\"###\"); return vPWn4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}