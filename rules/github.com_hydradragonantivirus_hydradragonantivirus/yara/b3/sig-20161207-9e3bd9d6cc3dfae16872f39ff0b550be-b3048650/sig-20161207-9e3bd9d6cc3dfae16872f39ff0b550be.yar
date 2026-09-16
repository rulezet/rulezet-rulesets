rule sig_20161207_9e3bd9d6cc3dfae16872f39ff0b550be {
  meta:
    description = "datamaliciousorder - file 20161207_9e3bd9d6cc3dfae16872f39ff0b550be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f997418dd0b67693cdb0d0b81e847c5cbda3c485582c33c84facfac4da18d98b"

  strings:
    $s1 = "var vOu8 = new Function(\"vBEu7\", '{var vGKw5 = new Date();vGKw5[\"setUTCFullYear\"](\"2003\");if (vGKw5.getUTCFullYear().toStr" ascii
    $s2 = "var vOu8 = new Function(\"vBEu7\", '{var vGKw5 = new Date();vGKw5[\"setUTCFullYear\"](\"2003\");if (vGKw5.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vXb8 = vBEu7.split(\"###\"); return vXb8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vMu6 = new Function(\"vBEu7\", '{return vBEu7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}