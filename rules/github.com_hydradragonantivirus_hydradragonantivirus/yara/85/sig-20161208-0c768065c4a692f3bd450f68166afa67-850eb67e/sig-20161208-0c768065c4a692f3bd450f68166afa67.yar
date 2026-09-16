rule sig_20161208_0c768065c4a692f3bd450f68166afa67 {
  meta:
    description = "datamaliciousorder - file 20161208_0c768065c4a692f3bd450f68166afa67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fd5d0b459bee1ba69a6c8279c70fb8b8993e73a13af42f549c4140a08f6728e"

  strings:
    $s1 = "2 = new Date();vZTy2[\"setUTC\"+\"FullYear\"](\"2003\");if (vZTy2.getUTCFullYear().toString(10) == \"2003\") {var vASz2 = vVDn3." ascii
    $s2 = "var vINd4 = new Function(\"vVDn3\", '{return vVDn3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHy0 = new Function(\"vVD" ascii
    $s3 = "var vINd4 = new Function(\"vVDn3\", '{return vVDn3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHy0 = new Function(\"vVD" ascii
    $s4 = "###\"); return vASz2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}