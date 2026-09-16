rule sig_20161208_49cb32441c162699488a185a7dc471a4 {
  meta:
    description = "datamaliciousorder - file 20161208_49cb32441c162699488a185a7dc471a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1310f8c37841a96a9f77195364b5281d800263135e1d1c04d59775d0ec6ee900"

  strings:
    $s1 = "k8 = new Date();vPLk8[\"setUTC\"+\"FullYear\"](\"2003\");if (vPLk8.getUTCFullYear().toString(10) == \"2003\") {var vECy6 = vSAx2" ascii
    $s2 = "var vTNf0 = new Function(\"vSAx2\", '{return vSAx2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEDe1 = new Function(\"vS" ascii
    $s3 = "var vTNf0 = new Function(\"vSAx2\", '{return vSAx2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEDe1 = new Function(\"vS" ascii
    $s4 = "####\"); return vECy6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}