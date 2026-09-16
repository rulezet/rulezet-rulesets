rule sig_20161208_1c5375b27d31c2b68b6b0a63eca966bd {
  meta:
    description = "datamaliciousorder - file 20161208_1c5375b27d31c2b68b6b0a63eca966bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "820b5149706c761e19712989e4a9659d1a5658b060a3127a0c474eef8873ab5e"

  strings:
    $s1 = "var vNXf1 = new Function(\"vIr4\", '{return vIr4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHe2 = new Function(\"vIr4" ascii
    $s2 = "new Date();vIt6[\"setUTC\"+\"FullYear\"](\"2003\");if (vIt6.getUTCFullYear().toString(10) == \"2003\") {var vRGe0 = vIr4.split(" ascii
    $s3 = "return vRGe0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNXf1 = new Function(\"vIr4\", '{return vIr4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHe2 = new Function(\"vIr4" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}