rule sig_20161207_64b4f0156cc096d1b72b0f95e4219a31 {
  meta:
    description = "datamaliciousorder - file 20161207_64b4f0156cc096d1b72b0f95e4219a31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5335e4442dd8586a576680e7f5d98715019f74ab4551632e7566fed4ef12a73e"

  strings:
    $s1 = " new Date();vXQu6[\"setUTCFullYear\"](\"2003\");if (vXQu6.getUTCFullYear().toString(10) == \"2003\") {var vPk1 = vXt3.split(\"##" ascii
    $s2 = "var vFs7 = new Function(\"vXt3\", '{return vXt3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZCb4 = new Function(\"vXt3" ascii
    $s3 = "eturn vPk1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vFs7 = new Function(\"vXt3\", '{return vXt3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZCb4 = new Function(\"vXt3" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}