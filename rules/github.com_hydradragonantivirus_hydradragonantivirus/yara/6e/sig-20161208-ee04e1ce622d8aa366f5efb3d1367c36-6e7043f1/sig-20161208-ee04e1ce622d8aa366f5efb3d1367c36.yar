rule sig_20161208_ee04e1ce622d8aa366f5efb3d1367c36 {
  meta:
    description = "datamaliciousorder - file 20161208_ee04e1ce622d8aa366f5efb3d1367c36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a94e36e3b85dbd75ffead9c6da3db4ddd85c375a23b38591392fc1ed35f79fc"

  strings:
    $s1 = "new Date();vFv2[\"setUTC\"+\"FullYear\"](\"2003\");if (vFv2.getUTCFullYear().toString(10) == \"2003\") {var vXz7 = vGb8.split(\"" ascii
    $s2 = "var vWJc4 = new Function(\"vGb8\", '{return vGb8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDc8 = new Function(\"vGb8" ascii
    $s3 = "eturn vXz7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vWJc4 = new Function(\"vGb8\", '{return vGb8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDc8 = new Function(\"vGb8" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}