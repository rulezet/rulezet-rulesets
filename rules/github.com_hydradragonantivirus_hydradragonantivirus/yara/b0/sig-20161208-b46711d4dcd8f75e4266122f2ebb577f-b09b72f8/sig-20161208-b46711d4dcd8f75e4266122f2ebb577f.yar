rule sig_20161208_b46711d4dcd8f75e4266122f2ebb577f {
  meta:
    description = "datamaliciousorder - file 20161208_b46711d4dcd8f75e4266122f2ebb577f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81db8ccd965b058d7fac679de8aed9ddf06a2b77ae896dd18689cc8034752870"

  strings:
    $s1 = "e0 = new Date();vIVe0[\"setUTC\"+\"FullYear\"](\"2003\");if (vIVe0.getUTCFullYear().toString(10) == \"2003\") {var vKTu1 = vTXc8" ascii
    $s2 = "var vZRz7 = new Function(\"vTXc8\", '{return vTXc8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vONp9 = new Function(\"vT" ascii
    $s3 = "var vZRz7 = new Function(\"vTXc8\", '{return vTXc8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vONp9 = new Function(\"vT" ascii
    $s4 = "####\"); return vKTu1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}