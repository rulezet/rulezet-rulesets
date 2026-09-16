rule sig_20161208_843c7196680b7d4ec6d193172fb33f13 {
  meta:
    description = "datamaliciousorder - file 20161208_843c7196680b7d4ec6d193172fb33f13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1725f03691212321d7dded0f1578347c892a3c81c805b647631fcf6cadc936b"

  strings:
    $s1 = "new Date();vSf6[\"setUTC\"+\"FullYear\"](\"2003\");if (vSf6.getUTCFullYear().toString(10) == \"2003\") {var vRw2 = vNw7.split(\"" ascii
    $s2 = "var vQc0 = new Function(\"vNw7\", '{return vNw7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKXr2 = new Function(\"vNw7" ascii
    $s3 = "eturn vRw2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vQc0 = new Function(\"vNw7\", '{return vNw7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKXr2 = new Function(\"vNw7" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}