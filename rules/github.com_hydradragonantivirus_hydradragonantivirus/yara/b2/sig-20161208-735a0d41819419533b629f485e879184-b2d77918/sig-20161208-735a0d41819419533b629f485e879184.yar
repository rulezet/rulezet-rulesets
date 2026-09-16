rule sig_20161208_735a0d41819419533b629f485e879184 {
  meta:
    description = "datamaliciousorder - file 20161208_735a0d41819419533b629f485e879184.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b08d702f31f2ed1a2438f52027b501d916c3b3a30cae27a656fa5a082ce47107"

  strings:
    $s1 = "w3 = new Date();vZCw3[\"setUTC\"+\"FullYear\"](\"2003\");if (vZCw3.getUTCFullYear().toString(10) == \"2003\") {var vOi7 = vOLv6." ascii
    $s2 = "var vPVj1 = new Function(\"vOLv6\", '{return vOLv6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAPr2 = new Function(\"vO" ascii
    $s3 = "###\"); return vOi7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vPVj1 = new Function(\"vOLv6\", '{return vOLv6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAPr2 = new Function(\"vO" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}