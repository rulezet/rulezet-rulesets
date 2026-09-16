rule sig_20161207_4ab6ffdf22ec36babe97ddf87e2d35f0 {
  meta:
    description = "datamaliciousorder - file 20161207_4ab6ffdf22ec36babe97ddf87e2d35f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9d19477c8a07b142261f56d6563fb9ae070a544ecdcf1157f88cc78aa5a54f1"

  strings:
    $s1 = "var vUj5 = new Function(\"vAo0\", '{var vFx7 = new Date();vFx7[\"setUTCFullYear\"](\"2003\");if (vFx7.getUTCFullYear().toString(" ascii
    $s2 = "var vUj5 = new Function(\"vAo0\", '{var vFx7 = new Date();vFx7[\"setUTCFullYear\"](\"2003\");if (vFx7.getUTCFullYear().toString(" ascii
    $s3 = "var vVx9 = new Function(\"vAo0\", '{return vAo0.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vKAf8 = vAo0.split(\"###\"); return vKAf8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}