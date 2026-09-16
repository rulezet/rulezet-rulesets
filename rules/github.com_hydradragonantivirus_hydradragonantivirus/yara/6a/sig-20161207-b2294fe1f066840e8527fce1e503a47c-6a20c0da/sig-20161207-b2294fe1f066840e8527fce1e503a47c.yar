rule sig_20161207_b2294fe1f066840e8527fce1e503a47c {
  meta:
    description = "datamaliciousorder - file 20161207_b2294fe1f066840e8527fce1e503a47c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b6281027ba2e1a1ff81f24a6818ad2a0aa42dc76dfb987290bab2b441963c0b"

  strings:
    $s1 = "var vIk7 = new Function(\"vFXv2\", '{var vGWu1 = new Date();vGWu1[\"setUTCFullYear\"](\"2003\");if (vGWu1.getUTCFullYear().toStr" ascii
    $s2 = "var vIk7 = new Function(\"vFXv2\", '{var vGWu1 = new Date();vGWu1[\"setUTCFullYear\"](\"2003\");if (vGWu1.getUTCFullYear().toStr" ascii
    $s3 = "var vYp4 = new Function(\"vFXv2\", '{return vFXv2.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vHd5 = vFXv2.split(\"###\"); return vHd5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}