rule sig_20161208_2d33e7a40d7a4b720e9f5cfc7f3bfe3b {
  meta:
    description = "datamaliciousorder - file 20161208_2d33e7a40d7a4b720e9f5cfc7f3bfe3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab445922c1a25c23d4fb6d5ebc23c18aef7563bf4080d96a17d93799bdbf91de"

  strings:
    $s1 = "new Date();vYh3[\"setUTC\"+\"FullYear\"](\"2003\");if (vYh3.getUTCFullYear().toString(10) == \"2003\") {var vTx3 = vPy1.split(\"" ascii
    $s2 = "var vUSz8 = new Function(\"vPy1\", '{return vPy1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVj4 = new Function(\"vPy1" ascii
    $s3 = "eturn vTx3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vUSz8 = new Function(\"vPy1\", '{return vPy1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVj4 = new Function(\"vPy1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}