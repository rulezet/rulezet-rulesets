rule sig_20161207_405ca2e635dd65ad401f3b08007725ce {
  meta:
    description = "datamaliciousorder - file 20161207_405ca2e635dd65ad401f3b08007725ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4dde09885a227310e401955407d0a7c65b8340991001d0a7df33144542c5698a"

  strings:
    $s1 = "var vBj6 = new Function(\"vAj8\", '{var vBSk2 = new Date();vBSk2[\"setUTCFullYear\"](\"2003\");if (vBSk2.getUTCFullYear().toStri" ascii
    $s2 = "var vBj6 = new Function(\"vAj8\", '{var vBSk2 = new Date();vBSk2[\"setUTCFullYear\"](\"2003\");if (vBSk2.getUTCFullYear().toStri" ascii
    $s3 = " == \"2003\") {var vKm9 = vAj8.split(\"###\"); return vKm9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vAYy6 = new Function(\"vAj8\", '{return vAj8.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}