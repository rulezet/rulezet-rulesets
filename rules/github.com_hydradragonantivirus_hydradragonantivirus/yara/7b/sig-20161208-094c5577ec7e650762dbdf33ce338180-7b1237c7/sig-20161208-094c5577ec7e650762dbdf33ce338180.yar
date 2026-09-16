rule sig_20161208_094c5577ec7e650762dbdf33ce338180 {
  meta:
    description = "datamaliciousorder - file 20161208_094c5577ec7e650762dbdf33ce338180.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9f0e9799c346f54dbbbe552ca23243c3099d22aecd46d1b6f1a8217d5b8f831"

  strings:
    $s1 = "var vId9 = new Function(\"vFGv4\", '{return vFGv4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKEw1 = new Function(\"vFG" ascii
    $s2 = "7 = new Date();vWZw7[\"setUTC\"+\"FullYear\"](\"2003\");if (vWZw7.getUTCFullYear().toString(10) == \"2003\") {var vZBo7 = vFGv4." ascii
    $s3 = "###\"); return vZBo7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vId9 = new Function(\"vFGv4\", '{return vFGv4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKEw1 = new Function(\"vFG" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}