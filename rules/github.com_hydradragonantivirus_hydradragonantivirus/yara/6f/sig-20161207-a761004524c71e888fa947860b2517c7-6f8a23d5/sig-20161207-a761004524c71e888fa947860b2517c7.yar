rule sig_20161207_a761004524c71e888fa947860b2517c7 {
  meta:
    description = "datamaliciousorder - file 20161207_a761004524c71e888fa947860b2517c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec61f1b32427b2b3e365136cee509d9ddf88a7fd1f9e46ec7af4b2f583ff913e"

  strings:
    $s1 = "var vMl3 = new Function(\"vUt4\", '{return vUt4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQYc4 = new Function(\"vUt4" ascii
    $s2 = " new Date();vQBb8[\"setUTCFullYear\"](\"2003\");if (vQBb8.getUTCFullYear().toString(10) == \"2003\") {var vRd2 = vUt4.split(\"##" ascii
    $s3 = "var vMl3 = new Function(\"vUt4\", '{return vUt4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQYc4 = new Function(\"vUt4" ascii
    $s4 = "eturn vRd2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}