rule sig_20161208_b1f80190a0b0873a933365694e43dde7 {
  meta:
    description = "datamaliciousorder - file 20161208_b1f80190a0b0873a933365694e43dde7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4eaa267fc21ed0a687cad44341c5888467befb603cd7c2f7067ab79726b1787a"

  strings:
    $s1 = "var vGQy6 = new Function(\"vLYh3\", '{return vLYh3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMd7 = new Function(\"vLY" ascii
    $s2 = "5 = new Date();vMAw5[\"setUTC\"+\"FullYear\"](\"2003\");if (vMAw5.getUTCFullYear().toString(10) == \"2003\") {var vNe6 = vLYh3.s" ascii
    $s3 = "var vGQy6 = new Function(\"vLYh3\", '{return vLYh3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMd7 = new Function(\"vLY" ascii
    $s4 = "##\"); return vNe6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}