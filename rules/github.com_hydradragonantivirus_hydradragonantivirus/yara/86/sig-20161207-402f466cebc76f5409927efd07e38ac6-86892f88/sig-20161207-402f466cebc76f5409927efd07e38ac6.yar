rule sig_20161207_402f466cebc76f5409927efd07e38ac6 {
  meta:
    description = "datamaliciousorder - file 20161207_402f466cebc76f5409927efd07e38ac6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bc164c7a51fd6254ea55e03b6ecdd11d8bf2eec129a494477bc6d129185e32b"

  strings:
    $s1 = "var vXJt0 = new Function(\"vTs3\", '{var vDUt5 = new Date();vDUt5[\"setUTCFullYear\"](\"2003\");if (vDUt5.getUTCFullYear().toStr" ascii
    $s2 = "var vXJt0 = new Function(\"vTs3\", '{var vDUt5 = new Date();vDUt5[\"setUTCFullYear\"](\"2003\");if (vDUt5.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vBz1 = vTs3.split(\"###\"); return vBz1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vNOo7 = new Function(\"vTs3\", '{return vTs3.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}