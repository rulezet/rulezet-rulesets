rule sig_20161207_6bc1e32c1745a724a198117abe12a857 {
  meta:
    description = "datamaliciousorder - file 20161207_6bc1e32c1745a724a198117abe12a857.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c07deff6f012be57df29b1ff4bb622a51b2f9cd248fb6cf1e935035d4c05407e"

  strings:
    $s1 = "new Date();vTg0[\"setUTCFullYear\"](\"2003\");if (vTg0.getUTCFullYear().toString(10) == \"2003\") {var vLo6 = vWi8.split(\"####" ascii
    $s2 = "var vZDv9 = new Function(\"vWi8\", '{return vWi8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAn6 = new Function(\"vWi8" ascii
    $s3 = "rn vLo6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vZDv9 = new Function(\"vWi8\", '{return vWi8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAn6 = new Function(\"vWi8" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}