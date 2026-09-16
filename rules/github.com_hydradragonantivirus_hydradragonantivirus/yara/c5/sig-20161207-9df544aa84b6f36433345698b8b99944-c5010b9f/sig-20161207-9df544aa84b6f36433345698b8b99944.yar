rule sig_20161207_9df544aa84b6f36433345698b8b99944 {
  meta:
    description = "datamaliciousorder - file 20161207_9df544aa84b6f36433345698b8b99944.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd3d834d00b9ac5566b15dec312018b8e54772a4c49c3c2e958396de35bd5b26"

  strings:
    $s1 = "var vAIs8 = new Function(\"vEy8\", '{var vOTj3 = new Date();vOTj3[\"setUTCFullYear\"](\"2003\");if (vOTj3.getUTCFullYear().toStr" ascii
    $s2 = "var vAIs8 = new Function(\"vEy8\", '{var vOTj3 = new Date();vOTj3[\"setUTCFullYear\"](\"2003\");if (vOTj3.getUTCFullYear().toStr" ascii
    $s3 = "var vMTl4 = new Function(\"vEy8\", '{return vEy8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vHCb6 = vEy8.split(\"###\"); return vHCb6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}