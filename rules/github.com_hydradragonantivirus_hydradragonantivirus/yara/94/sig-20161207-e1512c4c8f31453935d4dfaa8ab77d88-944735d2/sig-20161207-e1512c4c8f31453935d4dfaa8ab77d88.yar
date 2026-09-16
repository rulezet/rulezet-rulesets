rule sig_20161207_e1512c4c8f31453935d4dfaa8ab77d88 {
  meta:
    description = "datamaliciousorder - file 20161207_e1512c4c8f31453935d4dfaa8ab77d88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80546cf064925f5a71fa3ed93265733ee980f434cdb11368de89009a20783112"

  strings:
    $s1 = "var vBi1 = new Function(\"vSn2\", '{return vSn2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCz9 = new Function(\"vSn2\"" ascii
    $s2 = "ew Date();vZn1[\"setUTCFullYear\"](\"2003\");if (vZn1.getUTCFullYear().toString(10) == \"2003\") {var vBf0 = vSn2.split(\"####\"" ascii
    $s3 = "var vBi1 = new Function(\"vSn2\", '{return vSn2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCz9 = new Function(\"vSn2\"" ascii
    $s4 = "n vBf0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}