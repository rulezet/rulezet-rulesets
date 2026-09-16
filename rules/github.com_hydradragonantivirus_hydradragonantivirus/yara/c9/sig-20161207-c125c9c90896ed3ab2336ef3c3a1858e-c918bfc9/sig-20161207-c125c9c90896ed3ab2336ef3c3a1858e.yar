rule sig_20161207_c125c9c90896ed3ab2336ef3c3a1858e {
  meta:
    description = "datamaliciousorder - file 20161207_c125c9c90896ed3ab2336ef3c3a1858e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d420dff5920d2b10af432a1abab5f3dc0ee37f56d3b5b8cfd2e29c6369d23e05"

  strings:
    $s1 = " = new Date();vPf8[\"setUTCFullYear\"](\"2003\");if (vPf8.getUTCFullYear().toString(10) == \"2003\") {var vUh7 = vUZe8.split(\"#" ascii
    $s2 = "var vSEi3 = new Function(\"vUZe8\", '{return vUZe8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCe0 = new Function(\"vUZ" ascii
    $s3 = "return vUh7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vSEi3 = new Function(\"vUZe8\", '{return vUZe8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCe0 = new Function(\"vUZ" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}