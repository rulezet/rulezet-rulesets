rule sig_20161208_f86016482163fbbe773263852cc9815d {
  meta:
    description = "datamaliciousorder - file 20161208_f86016482163fbbe773263852cc9815d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80cc5c9cecd2a1952a66b958d3afb1f5c60dc9697e95892a39d035af8d6ada60"

  strings:
    $s1 = "var vHr9 = new Function(\"vHMo3\", '{return vHMo3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vULz8 = new Function(\"vHM" ascii
    $s2 = " = new Date();vVt0[\"setUTC\"+\"FullYear\"](\"2003\");if (vVt0.getUTCFullYear().toString(10) == \"2003\") {var vPVm8 = vHMo3.spl" ascii
    $s3 = "var vHr9 = new Function(\"vHMo3\", '{return vHMo3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vULz8 = new Function(\"vHM" ascii
    $s4 = "\"); return vPVm8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}