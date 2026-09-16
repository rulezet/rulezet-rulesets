rule sig_20161207_ecbdbd62a49eb46930c3070b6612d90b {
  meta:
    description = "datamaliciousorder - file 20161207_ecbdbd62a49eb46930c3070b6612d90b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb17e2b66692424ce0117864672c2af19f0bd6efcbbc27718f79c2eed945ab89"

  strings:
    $s1 = "var vGMj6 = new Function(\"vDVb2\", '{return vDVb2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKv5 = new Function(\"vDV" ascii
    $s2 = "6 = new Date();vXDj6[\"setUTCFullYear\"](\"2003\");if (vXDj6.getUTCFullYear().toString(10) == \"2003\") {var vWk7 = vDVb2.split(" ascii
    $s3 = "var vGMj6 = new Function(\"vDVb2\", '{return vDVb2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKv5 = new Function(\"vDV" ascii
    $s4 = "); return vWk7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}