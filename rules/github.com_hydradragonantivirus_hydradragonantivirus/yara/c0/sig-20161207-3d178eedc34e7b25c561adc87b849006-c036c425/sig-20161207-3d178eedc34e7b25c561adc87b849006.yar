rule sig_20161207_3d178eedc34e7b25c561adc87b849006 {
  meta:
    description = "datamaliciousorder - file 20161207_3d178eedc34e7b25c561adc87b849006.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "024faeb7909c8373f82d3efcfc090d0aefa354c128298edc71b5d63ff677c452"

  strings:
    $s1 = "var vBEb7 = new Function(\"vAm5\", '{var vQi3 = new Date();vQi3[\"setUTCFullYear\"](\"2003\");if (vQi3.getUTCFullYear().toString" ascii
    $s2 = "var vBEb7 = new Function(\"vAm5\", '{var vQi3 = new Date();vQi3[\"setUTCFullYear\"](\"2003\");if (vQi3.getUTCFullYear().toString" ascii
    $s3 = "var vEq7 = new Function(\"vAm5\", '{return vAm5.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vKRk5 = vAm5.split(\"###\"); return vKRk5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}