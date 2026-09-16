rule sig_20161207_e6e49107dcfa5c4eaaeb04f280d09a1a {
  meta:
    description = "datamaliciousorder - file 20161207_e6e49107dcfa5c4eaaeb04f280d09a1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90ec7296358c42359d57e55ef8a81c1fee193ff9d35ac0aae17b47ef4a9273b7"

  strings:
    $s1 = "var vIg1 = new Function(\"vGd8\", '{var vBu1 = new Date();vBu1[\"setUTCFullYear\"](\"2003\");if (vBu1.getUTCFullYear().toString(" ascii
    $s2 = "var vIg1 = new Function(\"vGd8\", '{var vBu1 = new Date();vBu1[\"setUTCFullYear\"](\"2003\");if (vBu1.getUTCFullYear().toString(" ascii
    $s3 = "var vEo9 = new Function(\"vGd8\", '{return vGd8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vLu7 = vGd8.split(\"###\"); return vLu7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}