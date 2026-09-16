rule sig_20161207_1e84170804b2fe32f63f027aab0f24d8 {
  meta:
    description = "datamaliciousorder - file 20161207_1e84170804b2fe32f63f027aab0f24d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b70377763902f7deda8106de97f2fb4904146c36a6ddef2aadb068f74781693"

  strings:
    $s1 = "var vMh5 = new Function(\"vRr3\", '{var vUz2 = new Date();vUz2[\"setUTCFullYear\"](\"2003\");if (vUz2.getUTCFullYear().toString(" ascii
    $s2 = "var vMh5 = new Function(\"vRr3\", '{var vUz2 = new Date();vUz2[\"setUTCFullYear\"](\"2003\");if (vUz2.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vNEd3 = vRr3.split(\"###\"); return vNEd3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vDf8 = new Function(\"vRr3\", '{return vRr3.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}