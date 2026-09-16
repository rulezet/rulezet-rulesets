rule sig_20161207_f2e556c2246292d2eafbad880115bba3 {
  meta:
    description = "datamaliciousorder - file 20161207_f2e556c2246292d2eafbad880115bba3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3c4266d59458838c07220e9c01272b8e27fab579b2c3c382ac58f6be4e99604"

  strings:
    $s1 = " new Date();vOBd4[\"setUTCFullYear\"](\"2003\");if (vOBd4.getUTCFullYear().toString(10) == \"2003\") {var vBAl6 = vAc8.split(\"#" ascii
    $s2 = "var vRSq4 = new Function(\"vAc8\", '{return vAc8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBn5 = new Function(\"vAc8" ascii
    $s3 = "var vRSq4 = new Function(\"vAc8\", '{return vAc8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBn5 = new Function(\"vAc8" ascii
    $s4 = "return vBAl6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}