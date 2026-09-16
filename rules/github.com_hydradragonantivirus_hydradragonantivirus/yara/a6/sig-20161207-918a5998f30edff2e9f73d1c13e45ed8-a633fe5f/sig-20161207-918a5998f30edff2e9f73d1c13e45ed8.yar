rule sig_20161207_918a5998f30edff2e9f73d1c13e45ed8 {
  meta:
    description = "datamaliciousorder - file 20161207_918a5998f30edff2e9f73d1c13e45ed8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed70d8e56f3df6ca9bafca1cb050a5ba8c20a6b913fa278a93a37a67d1246891"

  strings:
    $s1 = "var vBe8 = new Function(\"vUXp1\", '{var vHOz9 = new Date();vHOz9[\"setUTCFullYear\"](\"2003\");if (vHOz9.getUTCFullYear().toStr" ascii
    $s2 = "var vBe8 = new Function(\"vUXp1\", '{var vHOz9 = new Date();vHOz9[\"setUTCFullYear\"](\"2003\");if (vHOz9.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vHUo6 = vUXp1.split(\"###\"); return vHUo6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vGKq6 = new Function(\"vUXp1\", '{return vUXp1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}