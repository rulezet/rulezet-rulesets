rule sig_20161207_fae0afbad15a44e5ca716c2ef535037d {
  meta:
    description = "datamaliciousorder - file 20161207_fae0afbad15a44e5ca716c2ef535037d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "219c0bed48217af10e03d58c682503e0aaf8d96c849a3824808c6f918a8747c3"

  strings:
    $s1 = "var vPOd8 = new Function(\"vXm1\", '{return vXm1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMNx4 = new Function(\"vXm1" ascii
    $s2 = " new Date();vBc6[\"setUTCFullYear\"](\"2003\");if (vBc6.getUTCFullYear().toString(10) == \"2003\") {var vCv9 = vXm1.split(\"####" ascii
    $s3 = "var vPOd8 = new Function(\"vXm1\", '{return vXm1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMNx4 = new Function(\"vXm1" ascii
    $s4 = "urn vCv9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}