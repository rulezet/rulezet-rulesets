rule sig_20161207_0d042e91c8d55bffba2c999f5d7285c3 {
  meta:
    description = "datamaliciousorder - file 20161207_0d042e91c8d55bffba2c999f5d7285c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba1b6b176a0d7051b52be970f4adca7cf3fee0f15a86ac64ed72f90047465e9f"

  strings:
    $s1 = "var vTCw5 = new Function(\"vIZx0\", '{var vCu6 = new Date();vCu6[\"setUTCFullYear\"](\"2003\");if (vCu6.getUTCFullYear().toStrin" ascii
    $s2 = "var vTCw5 = new Function(\"vIZx0\", '{var vCu6 = new Date();vCu6[\"setUTCFullYear\"](\"2003\");if (vCu6.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vFo4 = vIZx0.split(\"###\"); return vFo4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vMFj7 = new Function(\"vIZx0\", '{return vIZx0.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}