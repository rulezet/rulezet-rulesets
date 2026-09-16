rule sig_20161207_740025cf9c7bc0b7707d18890186bbc5 {
  meta:
    description = "datamaliciousorder - file 20161207_740025cf9c7bc0b7707d18890186bbc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "025c355ff9a7a91a7e8d44f44f8c7ca2aa89e46faa5b4ce679f5c1294fe0185f"

  strings:
    $s1 = "var vAf8 = new Function(\"vAy2\", '{var vKXr5 = new Date();vKXr5[\"setUTCFullYear\"](\"2003\");if (vKXr5.getUTCFullYear().toStri" ascii
    $s2 = "var vAf8 = new Function(\"vAy2\", '{var vKXr5 = new Date();vKXr5[\"setUTCFullYear\"](\"2003\");if (vKXr5.getUTCFullYear().toStri" ascii
    $s3 = " == \"2003\") {var vASq9 = vAy2.split(\"###\"); return vASq9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vINe0 = new Function(\"vAy2\", '{return vAy2.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}