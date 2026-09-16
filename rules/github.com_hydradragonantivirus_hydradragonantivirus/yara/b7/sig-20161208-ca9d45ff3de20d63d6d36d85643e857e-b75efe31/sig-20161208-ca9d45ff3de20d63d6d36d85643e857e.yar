rule sig_20161208_ca9d45ff3de20d63d6d36d85643e857e {
  meta:
    description = "datamaliciousorder - file 20161208_ca9d45ff3de20d63d6d36d85643e857e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1f36d125885976ed7128c5f38e1b47aaa28d79aa54908e60a01b18e1af16160"

  strings:
    $s1 = "= new Date();vWPx6[\"setUTC\"+\"FullYear\"](\"2003\");if (vWPx6.getUTCFullYear().toString(10) == \"2003\") {var vCs8 = vLd1.spli" ascii
    $s2 = "var vHGj7 = new Function(\"vLd1\", '{return vLd1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHCt0 = new Function(\"vLd1" ascii
    $s3 = "); return vCs8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vHGj7 = new Function(\"vLd1\", '{return vLd1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHCt0 = new Function(\"vLd1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}