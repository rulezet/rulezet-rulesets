rule sig_20161208_83bb1d1f00f81f714f976dd43295d2d7 {
  meta:
    description = "datamaliciousorder - file 20161208_83bb1d1f00f81f714f976dd43295d2d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dc7e39688be88eae3563d45f3568e8b26e8abb2b901483730b22fbc0fcf5717"

  strings:
    $s1 = "var vTx8 = new Function(\"vPt2\", '{return vPt2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNZb2 = new Function(\"vPt2" ascii
    $s2 = "new Date();vMv6[\"setUTC\"+\"FullYear\"](\"2003\");if (vMv6.getUTCFullYear().toString(10) == \"2003\") {var vHy0 = vPt2.split(\"" ascii
    $s3 = "var vTx8 = new Function(\"vPt2\", '{return vPt2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNZb2 = new Function(\"vPt2" ascii
    $s4 = "eturn vHy0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}