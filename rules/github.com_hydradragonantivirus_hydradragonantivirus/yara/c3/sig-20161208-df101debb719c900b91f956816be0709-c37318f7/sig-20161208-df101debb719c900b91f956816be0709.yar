rule sig_20161208_df101debb719c900b91f956816be0709 {
  meta:
    description = "datamaliciousorder - file 20161208_df101debb719c900b91f956816be0709.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1eb2a3b40b4211a90fd1ebff0b80e1ce6d41e2de85f1f1208acc3ee4265362a"

  strings:
    $s1 = "ew Date();vSv6[\"setUTC\"+\"FullYear\"](\"2003\");if (vSv6.getUTCFullYear().toString(10) == \"2003\") {var vXAy7 = vXd5.split(\"" ascii
    $s2 = "var vMj3 = new Function(\"vXd5\", '{return vXd5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVk0 = new Function(\"vXd5\"" ascii
    $s3 = "var vMj3 = new Function(\"vXd5\", '{return vXd5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVk0 = new Function(\"vXd5\"" ascii
    $s4 = "eturn vXAy7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}