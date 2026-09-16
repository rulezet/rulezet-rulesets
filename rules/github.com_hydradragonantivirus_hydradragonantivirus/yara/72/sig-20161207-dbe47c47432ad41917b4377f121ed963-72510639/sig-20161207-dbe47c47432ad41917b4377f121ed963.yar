rule sig_20161207_dbe47c47432ad41917b4377f121ed963 {
  meta:
    description = "datamaliciousorder - file 20161207_dbe47c47432ad41917b4377f121ed963.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "821d807179e7a08c438f367675c3174262df27063038fa3ab9b14d7fdda078da"

  strings:
    $s1 = "var vDe5 = new Function(\"vTXk5\", '{var vTf1 = new Date();vTf1[\"setUTCFullYear\"](\"2003\");if (vTf1.getUTCFullYear().toString" ascii
    $s2 = "var vDe5 = new Function(\"vTXk5\", '{var vTf1 = new Date();vTf1[\"setUTCFullYear\"](\"2003\");if (vTf1.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vMQm2 = vTXk5.split(\"###\"); return vMQm2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vWv5 = new Function(\"vTXk5\", '{return vTXk5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}