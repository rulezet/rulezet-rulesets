rule sig_20161207_0128587fc7c6ed1c84aeaca74a60d3d5 {
  meta:
    description = "datamaliciousorder - file 20161207_0128587fc7c6ed1c84aeaca74a60d3d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af73a46a65134bdd6c43528cfc8eb1ccaf3dc7a1adeb1dbb430b7add1a14be36"

  strings:
    $s1 = "var vQVw3 = new Function(\"vEe6\", '{var vVKf6 = new Date();vVKf6[\"setUTCFullYear\"](\"2003\");if (vVKf6.getUTCFullYear().toStr" ascii
    $s2 = "var vQVw3 = new Function(\"vEe6\", '{var vVKf6 = new Date();vVKf6[\"setUTCFullYear\"](\"2003\");if (vVKf6.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vAo9 = vEe6.split(\"###\"); return vAo9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vACd7 = new Function(\"vEe6\", '{return vEe6.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}