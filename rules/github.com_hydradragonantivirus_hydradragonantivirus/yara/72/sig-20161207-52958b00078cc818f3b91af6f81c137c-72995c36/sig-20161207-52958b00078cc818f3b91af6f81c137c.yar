rule sig_20161207_52958b00078cc818f3b91af6f81c137c {
  meta:
    description = "datamaliciousorder - file 20161207_52958b00078cc818f3b91af6f81c137c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3e158c0a9b2e1934f35dd0dab98ef49535d2cf5aa4d9db715b9c4c64581c977"

  strings:
    $s1 = "var vCEf2 = new Function(\"vPWf9\", '{var vFf2 = new Date();vFf2[\"setUTCFullYear\"](\"2003\");if (vFf2.getUTCFullYear().toStrin" ascii
    $s2 = "var vCEf2 = new Function(\"vPWf9\", '{var vFf2 = new Date();vFf2[\"setUTCFullYear\"](\"2003\");if (vFf2.getUTCFullYear().toStrin" ascii
    $s3 = "var vCu5 = new Function(\"vPWf9\", '{return vPWf9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vXOn1 = vPWf9.split(\"###\"); return vXOn1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}