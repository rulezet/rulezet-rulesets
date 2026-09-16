rule sig_20161207_8f3d9c16f9e6df6909afa18a2062e8ae {
  meta:
    description = "datamaliciousorder - file 20161207_8f3d9c16f9e6df6909afa18a2062e8ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cef087b927a95f08a353bf800e2e4ae55bb88b7fa0dd9847e32b2a95955ce1ea"

  strings:
    $s1 = "var vDu5 = new Function(\"vKPt2\", '{var vNCf5 = new Date();vNCf5[\"setUTCFullYear\"](\"2003\");if (vNCf5.getUTCFullYear().toStr" ascii
    $s2 = "var vDu5 = new Function(\"vKPt2\", '{var vNCf5 = new Date();vNCf5[\"setUTCFullYear\"](\"2003\");if (vNCf5.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vVNn0 = vKPt2.split(\"###\"); return vVNn0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vZp9 = new Function(\"vKPt2\", '{return vKPt2.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}