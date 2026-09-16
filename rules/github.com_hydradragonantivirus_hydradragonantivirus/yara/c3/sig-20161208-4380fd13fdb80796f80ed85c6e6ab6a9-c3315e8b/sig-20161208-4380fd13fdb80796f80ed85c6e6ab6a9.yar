rule sig_20161208_4380fd13fdb80796f80ed85c6e6ab6a9 {
  meta:
    description = "datamaliciousorder - file 20161208_4380fd13fdb80796f80ed85c6e6ab6a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b348082b1e761a032201cdf973d0864603379641a636c1ccf4028286a9912f7"

  strings:
    $s1 = "var vKLi2 = new Function(\"vQMd3\", '{return vQMd3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBLr7 = new Function(\"vQ" ascii
    $s2 = "4 = new Date();vJj4[\"setUTC\"+\"FullYear\"](\"2003\");if (vJj4.getUTCFullYear().toString(10) == \"2003\") {var vKw0 = vQMd3.spl" ascii
    $s3 = "\"); return vKw0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vKLi2 = new Function(\"vQMd3\", '{return vQMd3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBLr7 = new Function(\"vQ" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}