rule sig_20161208_1b4d022c79e6627d08c23cc97ae31a5c {
  meta:
    description = "datamaliciousorder - file 20161208_1b4d022c79e6627d08c23cc97ae31a5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1143c29adbf8b25fa7514136e9fc5f83c4d917f61cd263e60549ef68f7656112"

  strings:
    $s1 = "var vKVe7 = new Function(\"vHg0\", '{return vHg0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKRe5 = new Function(\"vHg0" ascii
    $s2 = "= new Date();vHWr2[\"setUTC\"+\"FullYear\"](\"2003\");if (vHWr2.getUTCFullYear().toString(10) == \"2003\") {var vYPh0 = vHg0.spl" ascii
    $s3 = "\"); return vYPh0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vKVe7 = new Function(\"vHg0\", '{return vHg0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKRe5 = new Function(\"vHg0" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}