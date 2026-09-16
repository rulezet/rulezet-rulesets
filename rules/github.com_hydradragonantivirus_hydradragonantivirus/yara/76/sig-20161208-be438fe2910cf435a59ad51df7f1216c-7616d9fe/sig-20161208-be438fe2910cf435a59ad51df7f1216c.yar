rule sig_20161208_be438fe2910cf435a59ad51df7f1216c {
  meta:
    description = "datamaliciousorder - file 20161208_be438fe2910cf435a59ad51df7f1216c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "611320963fe2f31bb5b4f633d19dcadf4c33852c604246c2c62343c9ce7e6f5b"

  strings:
    $s1 = "var vZXq8 = new Function(\"vOd8\", '{return vOd8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWZp7 = new Function(\"vOd8" ascii
    $s2 = "= new Date();vPGj8[\"setUTC\"+\"FullYear\"](\"2003\");if (vPGj8.getUTCFullYear().toString(10) == \"2003\") {var vVTr7 = vOd8.spl" ascii
    $s3 = "var vZXq8 = new Function(\"vOd8\", '{return vOd8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWZp7 = new Function(\"vOd8" ascii
    $s4 = "\"); return vVTr7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}