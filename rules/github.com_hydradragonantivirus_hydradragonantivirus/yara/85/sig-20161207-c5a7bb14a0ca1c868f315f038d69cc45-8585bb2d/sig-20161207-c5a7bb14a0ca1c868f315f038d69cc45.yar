rule sig_20161207_c5a7bb14a0ca1c868f315f038d69cc45 {
  meta:
    description = "datamaliciousorder - file 20161207_c5a7bb14a0ca1c868f315f038d69cc45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e509b0ce5edec738574fe229c35d3f0947dc2582e845a8f06f0a3d70dddc8eef"

  strings:
    $s1 = "var vEIk8 = new Function(\"vWCu2\", '{return vWCu2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIe8 = new Function(\"vWC" ascii
    $s2 = "9 = new Date();vCVf9[\"setUTCFullYear\"](\"2003\");if (vCVf9.getUTCFullYear().toString(10) == \"2003\") {var vPSe7 = vWCu2.split" ascii
    $s3 = "\"); return vPSe7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEIk8 = new Function(\"vWCu2\", '{return vWCu2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIe8 = new Function(\"vWC" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}