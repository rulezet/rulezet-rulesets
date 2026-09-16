rule sig_20161207_f70a7383d142976ca10da33dc7db454d {
  meta:
    description = "datamaliciousorder - file 20161207_f70a7383d142976ca10da33dc7db454d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c89e0720927d5989d7d0a04f15f1b2276d94f9cd6b38419100670806cd368207"

  strings:
    $s1 = "new Date();vKx4[\"setUTCFullYear\"](\"2003\");if (vKx4.getUTCFullYear().toString(10) == \"2003\") {var vFd8 = vBy2.split(\"####" ascii
    $s2 = "var vTr0 = new Function(\"vBy2\", '{return vBy2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHLe8 = new Function(\"vBy2" ascii
    $s3 = "var vTr0 = new Function(\"vBy2\", '{return vBy2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHLe8 = new Function(\"vBy2" ascii
    $s4 = "rn vFd8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}