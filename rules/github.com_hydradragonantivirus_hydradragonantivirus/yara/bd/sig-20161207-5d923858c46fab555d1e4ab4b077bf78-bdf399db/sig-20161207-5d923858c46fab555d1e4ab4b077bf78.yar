rule sig_20161207_5d923858c46fab555d1e4ab4b077bf78 {
  meta:
    description = "datamaliciousorder - file 20161207_5d923858c46fab555d1e4ab4b077bf78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0370a6dec6b4d3c2c5ec676ff00973ed48ff9d40adf85372a554e34d7ac851ff"

  strings:
    $s1 = "var vYn7 = new Function(\"vBr2\", '{return vBr2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOMq4 = new Function(\"vBr2" ascii
    $s2 = " new Date();vHRr7[\"setUTCFullYear\"](\"2003\");if (vHRr7.getUTCFullYear().toString(10) == \"2003\") {var vZUr2 = vBr2.split(\"#" ascii
    $s3 = "return vZUr2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vYn7 = new Function(\"vBr2\", '{return vBr2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOMq4 = new Function(\"vBr2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}