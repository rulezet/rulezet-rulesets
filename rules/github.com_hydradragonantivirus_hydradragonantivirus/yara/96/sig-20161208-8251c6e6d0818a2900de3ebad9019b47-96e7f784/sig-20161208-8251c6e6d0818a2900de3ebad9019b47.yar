rule sig_20161208_8251c6e6d0818a2900de3ebad9019b47 {
  meta:
    description = "datamaliciousorder - file 20161208_8251c6e6d0818a2900de3ebad9019b47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "650e37c7b92f6d1b48046443387764bc05782ec39f1dcaeb1d39691d09c9932b"

  strings:
    $s1 = "ew Date();vWe4[\"setUTC\"+\"FullYear\"](\"2003\");if (vWe4.getUTCFullYear().toString(10) == \"2003\") {var vGt1 = vOc2.split(\"#" ascii
    $s2 = "var vCd9 = new Function(\"vOc2\", '{return vOc2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLe2 = new Function(\"vOc2\"" ascii
    $s3 = "turn vGt1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vCd9 = new Function(\"vOc2\", '{return vOc2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLe2 = new Function(\"vOc2\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}