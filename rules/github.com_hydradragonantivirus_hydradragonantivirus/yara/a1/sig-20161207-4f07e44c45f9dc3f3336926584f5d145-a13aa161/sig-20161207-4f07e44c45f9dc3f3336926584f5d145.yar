rule sig_20161207_4f07e44c45f9dc3f3336926584f5d145 {
  meta:
    description = "datamaliciousorder - file 20161207_4f07e44c45f9dc3f3336926584f5d145.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df2085c8a951876bd9aeb84c374def59fc02fe7fced0c9b41b79ba27930d1b27"

  strings:
    $s1 = "9 = new Date();vFYg9[\"setUTCFullYear\"](\"2003\");if (vFYg9.getUTCFullYear().toString(10) == \"2003\") {var vJYp2 = vUJf2.split" ascii
    $s2 = "var vRx1 = new Function(\"vUJf2\", '{return vUJf2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEZq9 = new Function(\"vUJ" ascii
    $s3 = "var vRx1 = new Function(\"vUJf2\", '{return vUJf2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEZq9 = new Function(\"vUJ" ascii
    $s4 = "\"); return vJYp2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}