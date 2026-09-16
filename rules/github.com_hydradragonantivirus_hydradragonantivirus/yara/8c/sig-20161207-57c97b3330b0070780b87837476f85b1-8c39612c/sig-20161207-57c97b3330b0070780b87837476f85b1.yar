rule sig_20161207_57c97b3330b0070780b87837476f85b1 {
  meta:
    description = "datamaliciousorder - file 20161207_57c97b3330b0070780b87837476f85b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c67162d92640e8384b30be331d6c42e8b85deef8aa03fc1f99fcdd8813d05b0"

  strings:
    $s1 = "var vQIa0 = new Function(\"vXj1\", '{return vXj1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRu1 = new Function(\"vXj1" ascii
    $s2 = " new Date();vTEz3[\"setUTCFullYear\"](\"2003\");if (vTEz3.getUTCFullYear().toString(10) == \"2003\") {var vYu4 = vXj1.split(\"##" ascii
    $s3 = "eturn vYu4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vQIa0 = new Function(\"vXj1\", '{return vXj1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRu1 = new Function(\"vXj1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}