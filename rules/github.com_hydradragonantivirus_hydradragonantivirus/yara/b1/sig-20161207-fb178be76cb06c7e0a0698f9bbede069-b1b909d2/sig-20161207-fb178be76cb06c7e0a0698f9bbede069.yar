rule sig_20161207_fb178be76cb06c7e0a0698f9bbede069 {
  meta:
    description = "datamaliciousorder - file 20161207_fb178be76cb06c7e0a0698f9bbede069.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38c60cc7da18192b88b3ef9312f3a6d96efbf4c2d91ac0327232a9d6ac593bbc"

  strings:
    $s1 = "= new Date();vMg2[\"setUTCFullYear\"](\"2003\");if (vMg2.getUTCFullYear().toString(10) == \"2003\") {var vFe7 = vMNz5.split(\"##" ascii
    $s2 = "var vZm3 = new Function(\"vMNz5\", '{return vMNz5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRt8 = new Function(\"vMNz" ascii
    $s3 = "var vZm3 = new Function(\"vMNz5\", '{return vMNz5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRt8 = new Function(\"vMNz" ascii
    $s4 = "eturn vFe7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}