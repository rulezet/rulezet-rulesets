rule sig_20161207_5ba686c2eda74073aa10c3f2885ed20b {
  meta:
    description = "datamaliciousorder - file 20161207_5ba686c2eda74073aa10c3f2885ed20b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97a0008fa37f9046927cb67799d49cadfad024b6634d1da5b9284315f593c0b7"

  strings:
    $s1 = "var vUi9 = new Function(\"vZSh7\", '{var vKh4 = new Date();vKh4[\"setUTCFullYear\"](\"2003\");if (vKh4.getUTCFullYear().toString" ascii
    $s2 = "var vUi9 = new Function(\"vZSh7\", '{var vKh4 = new Date();vKh4[\"setUTCFullYear\"](\"2003\");if (vKh4.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vHv3 = vZSh7.split(\"###\"); return vHv3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vSTe2 = new Function(\"vZSh7\", '{return vZSh7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}