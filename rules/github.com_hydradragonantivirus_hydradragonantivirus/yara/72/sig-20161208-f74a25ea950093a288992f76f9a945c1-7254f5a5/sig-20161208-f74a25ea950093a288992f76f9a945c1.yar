rule sig_20161208_f74a25ea950093a288992f76f9a945c1 {
  meta:
    description = "datamaliciousorder - file 20161208_f74a25ea950093a288992f76f9a945c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96f2686cd1a08906010fb6087aab19e22361bce66da117175a55a03b85c891d0"

  strings:
    $s1 = "var vFl6 = new Function(\"vLf3\", '{return vLf3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPg6 = new Function(\"vLf3\"" ascii
    $s2 = "ew Date();vOc9[\"setUTC\"+\"FullYear\"](\"2003\");if (vOc9.getUTCFullYear().toString(10) == \"2003\") {var vTa6 = vLf3.split(\"#" ascii
    $s3 = "var vFl6 = new Function(\"vLf3\", '{return vLf3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPg6 = new Function(\"vLf3\"" ascii
    $s4 = "turn vTa6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}