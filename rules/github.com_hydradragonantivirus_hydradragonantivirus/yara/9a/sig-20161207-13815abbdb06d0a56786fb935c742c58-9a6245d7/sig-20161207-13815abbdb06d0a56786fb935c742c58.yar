rule sig_20161207_13815abbdb06d0a56786fb935c742c58 {
  meta:
    description = "datamaliciousorder - file 20161207_13815abbdb06d0a56786fb935c742c58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f59b391b1d42128e2e0f4b68a96b8a8f3e1dce6573a99575957fc25817bae6f"

  strings:
    $s1 = "var vIAc8 = new Function(\"vYs1\", '{var vINh2 = new Date();vINh2[\"setUTCFullYear\"](\"2003\");if (vINh2.getUTCFullYear().toStr" ascii
    $s2 = "var vIAc8 = new Function(\"vYs1\", '{var vINh2 = new Date();vINh2[\"setUTCFullYear\"](\"2003\");if (vINh2.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vJBe1 = vYs1.split(\"###\"); return vJBe1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vGe0 = new Function(\"vYs1\", '{return vYs1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}