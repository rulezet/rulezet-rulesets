rule sig_20161208_abe190ecbfc96585b5a3aaacc79f07e5 {
  meta:
    description = "datamaliciousorder - file 20161208_abe190ecbfc96585b5a3aaacc79f07e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d416fc56d803761412045f8cd6309e5b99a344841ea4407beb142209617c1027"

  strings:
    $s1 = "var vNDe9 = new Function(\"vQHy9\", '{return vQHy9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCQe3 = new Function(\"vQ" ascii
    $s2 = "x3 = new Date();vPQx3[\"setUTC\"+\"FullYear\"](\"2003\");if (vPQx3.getUTCFullYear().toString(10) == \"2003\") {var vIp2 = vQHy9." ascii
    $s3 = "###\"); return vIp2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNDe9 = new Function(\"vQHy9\", '{return vQHy9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCQe3 = new Function(\"vQ" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}