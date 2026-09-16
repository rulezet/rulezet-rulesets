rule sig_20161208_13feb57ffaa1fa2c10129e4ca21c0758 {
  meta:
    description = "datamaliciousorder - file 20161208_13feb57ffaa1fa2c10129e4ca21c0758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c35bd0fd37284a6fae47a8dd22134a0ec2ad1716b1e51266aac588b737821173"

  strings:
    $s1 = "r3 = new Date();vVNr3[\"setUTC\"+\"FullYear\"](\"2003\");if (vVNr3.getUTCFullYear().toString(10) == \"2003\") {var vJu3 = vWIs8." ascii
    $s2 = "var vKHr0 = new Function(\"vWIs8\", '{return vWIs8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCPg9 = new Function(\"vW" ascii
    $s3 = "###\"); return vJu3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vKHr0 = new Function(\"vWIs8\", '{return vWIs8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCPg9 = new Function(\"vW" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}