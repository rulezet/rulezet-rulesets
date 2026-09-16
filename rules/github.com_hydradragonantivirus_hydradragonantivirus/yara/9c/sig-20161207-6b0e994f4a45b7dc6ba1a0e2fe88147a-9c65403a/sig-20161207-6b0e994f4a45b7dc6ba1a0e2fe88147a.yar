rule sig_20161207_6b0e994f4a45b7dc6ba1a0e2fe88147a {
  meta:
    description = "datamaliciousorder - file 20161207_6b0e994f4a45b7dc6ba1a0e2fe88147a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c1153b3260faf39dd0a45b031d8f94cb38b24d5e51524418eefc0614229dd9a"

  strings:
    $s1 = "var vLRf5 = new Function(\"vEb4\", '{var vMPw7 = new Date();vMPw7[\"setUTCFullYear\"](\"2003\");if (vMPw7.getUTCFullYear().toStr" ascii
    $s2 = "var vLRf5 = new Function(\"vEb4\", '{var vMPw7 = new Date();vMPw7[\"setUTCFullYear\"](\"2003\");if (vMPw7.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vKo2 = vEb4.split(\"###\"); return vKo2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vBLv1 = new Function(\"vEb4\", '{return vEb4.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}