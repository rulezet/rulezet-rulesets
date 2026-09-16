rule sig_20161208_de31827dd9dd821f95679b0c014ffa91 {
  meta:
    description = "datamaliciousorder - file 20161208_de31827dd9dd821f95679b0c014ffa91.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7b9fc8113188b939f868f9ea30e83a4b98de4dcde860cde7c41e50b180a4e9a"

  strings:
    $s1 = "var vIm2 = new Function(\"vZj3\", '{return vZj3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRRh4 = new Function(\"vZj3" ascii
    $s2 = "new Date();vBm7[\"setUTC\"+\"FullYear\"](\"2003\");if (vBm7.getUTCFullYear().toString(10) == \"2003\") {var vHLo0 = vZj3.split(" ascii
    $s3 = "var vIm2 = new Function(\"vZj3\", '{return vZj3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRRh4 = new Function(\"vZj3" ascii
    $s4 = "return vHLo0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}