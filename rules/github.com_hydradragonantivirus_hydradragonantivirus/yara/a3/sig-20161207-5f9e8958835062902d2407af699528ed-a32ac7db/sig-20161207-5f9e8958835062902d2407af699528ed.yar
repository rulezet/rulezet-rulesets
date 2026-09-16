rule sig_20161207_5f9e8958835062902d2407af699528ed {
  meta:
    description = "datamaliciousorder - file 20161207_5f9e8958835062902d2407af699528ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7052706838a21eacaae37d3635e9d35c2dc2b47c50977118861df9724e450edd"

  strings:
    $s1 = "var vSRg5 = new Function(\"vXSr9\", '{var vKi6 = new Date();vKi6[\"setUTCFullYear\"](\"2003\");if (vKi6.getUTCFullYear().toStrin" ascii
    $s2 = "var vSRg5 = new Function(\"vXSr9\", '{var vKi6 = new Date();vKi6[\"setUTCFullYear\"](\"2003\");if (vKi6.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vRQj1 = vXSr9.split(\"###\"); return vRQj1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vGl6 = new Function(\"vXSr9\", '{return vXSr9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}