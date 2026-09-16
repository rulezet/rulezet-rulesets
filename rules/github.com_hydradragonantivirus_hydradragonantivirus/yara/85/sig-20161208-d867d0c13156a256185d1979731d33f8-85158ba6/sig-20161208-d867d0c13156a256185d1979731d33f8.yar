rule sig_20161208_d867d0c13156a256185d1979731d33f8 {
  meta:
    description = "datamaliciousorder - file 20161208_d867d0c13156a256185d1979731d33f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "147e86a6109257c7e3a756421d26a78bc844fe1bc2ffc95fe1e4f8630901e2d7"

  strings:
    $s1 = "new Date();vWBn7[\"setUTC\"+\"FullYear\"](\"2003\");if (vWBn7.getUTCFullYear().toString(10) == \"2003\") {var vGm8 = vWc5.split(" ascii
    $s2 = "var vPl3 = new Function(\"vWc5\", '{return vWc5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSn9 = new Function(\"vWc5\"" ascii
    $s3 = " return vGm8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vPl3 = new Function(\"vWc5\", '{return vWc5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSn9 = new Function(\"vWc5\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}