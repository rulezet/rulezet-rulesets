rule sig_20161208_0ad938091f8631b321c9040958e3d3c5 {
  meta:
    description = "datamaliciousorder - file 20161208_0ad938091f8631b321c9040958e3d3c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6489016d5c708f3c305f2740d37fe40c8d71922fb9270a7225c90e672a3f8ba1"

  strings:
    $s1 = "var vQr6 = new Function(\"vAg4\", '{return vAg4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHn7 = new Function(\"vAg4\"" ascii
    $s2 = "new Date();vBPe3[\"setUTC\"+\"FullYear\"](\"2003\");if (vBPe3.getUTCFullYear().toString(10) == \"2003\") {var vWHb6 = vAg4.split" ascii
    $s3 = "; return vWHb6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vQr6 = new Function(\"vAg4\", '{return vAg4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHn7 = new Function(\"vAg4\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}