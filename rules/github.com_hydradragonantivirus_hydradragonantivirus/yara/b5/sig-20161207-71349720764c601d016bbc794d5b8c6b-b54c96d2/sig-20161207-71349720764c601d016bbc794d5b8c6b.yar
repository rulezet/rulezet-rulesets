rule sig_20161207_71349720764c601d016bbc794d5b8c6b {
  meta:
    description = "datamaliciousorder - file 20161207_71349720764c601d016bbc794d5b8c6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a83fccba8361173bd5bfb348cbecb9756e6b96a5ea9274e63ca2f470c5b317a0"

  strings:
    $s1 = "var vXd4 = new Function(\"vZo0\", '{return vZo0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDb8 = new Function(\"vZo0\"" ascii
    $s2 = "ew Date();vOk9[\"setUTCFullYear\"](\"2003\");if (vOk9.getUTCFullYear().toString(10) == \"2003\") {var vBk9 = vZo0.split(\"####\"" ascii
    $s3 = "var vXd4 = new Function(\"vZo0\", '{return vZo0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDb8 = new Function(\"vZo0\"" ascii
    $s4 = "n vBk9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}