rule sig_20161207_c8254411f7f76f1b0e08eacca107d6b6 {
  meta:
    description = "datamaliciousorder - file 20161207_c8254411f7f76f1b0e08eacca107d6b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d15a0d4a1bffd5325be5c6a124dd4614d2aab284d00d2e22058f4873a3885cd"

  strings:
    $s1 = "new Date();vQr8[\"setUTCFullYear\"](\"2003\");if (vQr8.getUTCFullYear().toString(10) == \"2003\") {var vLOg1 = vMk7.split(\"####" ascii
    $s2 = "var vHl8 = new Function(\"vMk7\", '{return vMk7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGIh1 = new Function(\"vMk7" ascii
    $s3 = "urn vLOg1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vHl8 = new Function(\"vMk7\", '{return vMk7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGIh1 = new Function(\"vMk7" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}