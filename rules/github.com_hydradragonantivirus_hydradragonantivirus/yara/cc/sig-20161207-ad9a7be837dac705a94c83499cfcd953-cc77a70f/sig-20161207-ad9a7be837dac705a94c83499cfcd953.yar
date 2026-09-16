rule sig_20161207_ad9a7be837dac705a94c83499cfcd953 {
  meta:
    description = "datamaliciousorder - file 20161207_ad9a7be837dac705a94c83499cfcd953.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a07444fcf8e4cb74043bddf6ad2a69ce0cd621540c4472b2517adcb409f22744"

  strings:
    $s1 = "var vMVl1 = new Function(\"vWb7\", '{var vOPn5 = new Date();vOPn5[\"setUTCFullYear\"](\"2003\");if (vOPn5.getUTCFullYear().toStr" ascii
    $s2 = "var vMVl1 = new Function(\"vWb7\", '{var vOPn5 = new Date();vOPn5[\"setUTCFullYear\"](\"2003\");if (vOPn5.getUTCFullYear().toStr" ascii
    $s3 = "var vMMe3 = new Function(\"vWb7\", '{return vWb7.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vAKe0 = vWb7.split(\"###\"); return vAKe0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}