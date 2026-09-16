rule sig_20161207_290b391aba299468f26f102984e7945d {
  meta:
    description = "datamaliciousorder - file 20161207_290b391aba299468f26f102984e7945d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "325ebb62a7454782e4e34f2948c9d89aeb078a4ea3de9f713fe53fb6ffc5da66"

  strings:
    $s1 = "var vGLw9 = new Function(\"vMZd7\", '{var vBXm4 = new Date();vBXm4[\"setUTCFullYear\"](\"2003\");if (vBXm4.getUTCFullYear().toSt" ascii
    $s2 = "var vGLw9 = new Function(\"vMZd7\", '{var vBXm4 = new Date();vBXm4[\"setUTCFullYear\"](\"2003\");if (vBXm4.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vRm9 = vMZd7.split(\"###\"); return vRm9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vQAc9 = new Function(\"vMZd7\", '{return vMZd7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}