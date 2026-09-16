rule sig_20161208_9dedb5d22fa31cdc66e81238c90a7bd3 {
  meta:
    description = "datamaliciousorder - file 20161208_9dedb5d22fa31cdc66e81238c90a7bd3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "104464e8ecc70a6ad5b85f0672f61548658ef4ff38293a846081183cdc95e41a"

  strings:
    $s1 = "4 = new Date();vGSl4[\"setUTC\"+\"FullYear\"](\"2003\");if (vGSl4.getUTCFullYear().toString(10) == \"2003\") {var vNIg3 = vIOj1." ascii
    $s2 = "var vMt2 = new Function(\"vIOj1\", '{return vIOj1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWQm6 = new Function(\"vIO" ascii
    $s3 = "var vMt2 = new Function(\"vIOj1\", '{return vIOj1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWQm6 = new Function(\"vIO" ascii
    $s4 = "###\"); return vNIg3.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}