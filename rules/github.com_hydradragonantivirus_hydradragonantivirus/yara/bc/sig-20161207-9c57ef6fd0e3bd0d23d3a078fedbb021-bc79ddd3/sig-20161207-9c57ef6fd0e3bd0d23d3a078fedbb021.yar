rule sig_20161207_9c57ef6fd0e3bd0d23d3a078fedbb021 {
  meta:
    description = "datamaliciousorder - file 20161207_9c57ef6fd0e3bd0d23d3a078fedbb021.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c20b29776df8f3e01963a36ad260848fee602550d9791a77eed5aab4f336b2da"

  strings:
    $s1 = "var vULq3 = new Function(\"vBJl0\", '{var vQFf2 = new Date();vQFf2[\"setUTCFullYear\"](\"2003\");if (vQFf2.getUTCFullYear().toSt" ascii
    $s2 = "var vULq3 = new Function(\"vBJl0\", '{var vQFf2 = new Date();vQFf2[\"setUTCFullYear\"](\"2003\");if (vQFf2.getUTCFullYear().toSt" ascii
    $s3 = "var vCJf8 = new Function(\"vBJl0\", '{return vBJl0.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "0) == \"2003\") {var vHKy2 = vBJl0.split(\"###\"); return vHKy2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}