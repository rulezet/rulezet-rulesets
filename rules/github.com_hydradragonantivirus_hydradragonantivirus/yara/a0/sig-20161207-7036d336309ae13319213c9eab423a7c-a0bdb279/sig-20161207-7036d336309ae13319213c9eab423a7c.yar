rule sig_20161207_7036d336309ae13319213c9eab423a7c {
  meta:
    description = "datamaliciousorder - file 20161207_7036d336309ae13319213c9eab423a7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b1fab25166de89d2abbb57f028f6b3e7bea4badc0ac2321ab017dfa6f63076c"

  strings:
    $s1 = "var vXIc9 = new Function(\"vIn3\", '{var vIJk2 = new Date();vIJk2[\"setUTCFullYear\"](\"2003\");if (vIJk2.getUTCFullYear().toStr" ascii
    $s2 = "var vXIc9 = new Function(\"vIn3\", '{var vIJk2 = new Date();vIJk2[\"setUTCFullYear\"](\"2003\");if (vIJk2.getUTCFullYear().toStr" ascii
    $s3 = "var vRv5 = new Function(\"vIn3\", '{return vIn3.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vRXl5 = vIn3.split(\"###\"); return vRXl5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}