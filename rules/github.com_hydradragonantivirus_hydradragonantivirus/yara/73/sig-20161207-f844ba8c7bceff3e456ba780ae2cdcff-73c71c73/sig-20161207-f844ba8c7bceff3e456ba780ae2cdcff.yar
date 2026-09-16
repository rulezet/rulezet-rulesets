rule sig_20161207_f844ba8c7bceff3e456ba780ae2cdcff {
  meta:
    description = "datamaliciousorder - file 20161207_f844ba8c7bceff3e456ba780ae2cdcff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a05500c5e005ec6733ebc90bd22c758eddeeb880e132e6c44dd9cede4558b6f"

  strings:
    $s1 = "var vVr5 = new Function(\"vIZz6\", '{var vJg0 = new Date();vJg0[\"setUTCFullYear\"](\"2003\");if (vJg0.getUTCFullYear().toString" ascii
    $s2 = "var vVr5 = new Function(\"vIZz6\", '{var vJg0 = new Date();vJg0[\"setUTCFullYear\"](\"2003\");if (vJg0.getUTCFullYear().toString" ascii
    $s3 = "var vYs5 = new Function(\"vIZz6\", '{return vIZz6.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vQQt3 = vIZz6.split(\"###\"); return vQQt3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}