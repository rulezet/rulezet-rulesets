rule sig_20161207_edac5f787f2f7438f329a725b46095d8 {
  meta:
    description = "datamaliciousorder - file 20161207_edac5f787f2f7438f329a725b46095d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7e6fe6cca970bde684187fdcfe2d3b7998fdfdc85489ffd9b425e3a92487c8d"

  strings:
    $s1 = "var vIKl3 = new Function(\"vDNo8\", '{var vHu3 = new Date();vHu3[\"setUTCFullYear\"](\"2003\");if (vHu3.getUTCFullYear().toStrin" ascii
    $s2 = "var vIKl3 = new Function(\"vDNo8\", '{var vHu3 = new Date();vHu3[\"setUTCFullYear\"](\"2003\");if (vHu3.getUTCFullYear().toStrin" ascii
    $s3 = "var vDMn3 = new Function(\"vDNo8\", '{return vDNo8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vIe4 = vDNo8.split(\"###\"); return vIe4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}