rule sig_20161208_1b31273b14460558ec1ad21fffc1bed0 {
  meta:
    description = "datamaliciousorder - file 20161208_1b31273b14460558ec1ad21fffc1bed0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45814294a11364448d97a231729d9fd8e60fe932568e55ace254d4f258cbaf61"

  strings:
    $s1 = "var vQq3 = new Function(\"vCh0\", '{return vCh0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGDv6 = new Function(\"vCh0" ascii
    $s2 = " new Date();vUIp1[\"setUTC\"+\"FullYear\"](\"2003\");if (vUIp1.getUTCFullYear().toString(10) == \"2003\") {var vBVy6 = vCh0.spli" ascii
    $s3 = "); return vBVy6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vQq3 = new Function(\"vCh0\", '{return vCh0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGDv6 = new Function(\"vCh0" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}