rule sig_20161207_beb06f1538288f03b91ef236157dc51e {
  meta:
    description = "datamaliciousorder - file 20161207_beb06f1538288f03b91ef236157dc51e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ee89d4a2b4aeb872488dd67aed875ad2a63a8af52a41146958cf0a51ed4be1c"

  strings:
    $s1 = "var vISx9 = new Function(\"vCa0\", '{var vRv5 = new Date();vRv5[\"setUTCFullYear\"](\"2003\");if (vRv5.getUTCFullYear().toString" ascii
    $s2 = "var vISx9 = new Function(\"vCa0\", '{var vRv5 = new Date();vRv5[\"setUTCFullYear\"](\"2003\");if (vRv5.getUTCFullYear().toString" ascii
    $s3 = "var vGf8 = new Function(\"vCa0\", '{return vCa0.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vYFj0 = vCa0.split(\"###\"); return vYFj0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}