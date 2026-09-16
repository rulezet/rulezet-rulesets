rule sig_20161207_996315404d73ccda0d0866b6dedd2551 {
  meta:
    description = "datamaliciousorder - file 20161207_996315404d73ccda0d0866b6dedd2551.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4535e2cfd4c0e3f7e5a6c537798522b2d76671ae4c0ae379b2ff49bbcc797cc1"

  strings:
    $s1 = "var vTFy7 = new Function(\"vZn5\", '{var vAOi9 = new Date();vAOi9[\"setUTCFullYear\"](\"2003\");if (vAOi9.getUTCFullYear().toStr" ascii
    $s2 = "var vTFy7 = new Function(\"vZn5\", '{var vAOi9 = new Date();vAOi9[\"setUTCFullYear\"](\"2003\");if (vAOi9.getUTCFullYear().toStr" ascii
    $s3 = "var vHTd2 = new Function(\"vZn5\", '{return vZn5.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vRt3 = vZn5.split(\"###\"); return vRt3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}