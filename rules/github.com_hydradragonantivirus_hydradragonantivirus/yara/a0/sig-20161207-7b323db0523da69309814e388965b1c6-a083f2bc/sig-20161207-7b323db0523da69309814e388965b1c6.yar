rule sig_20161207_7b323db0523da69309814e388965b1c6 {
  meta:
    description = "datamaliciousorder - file 20161207_7b323db0523da69309814e388965b1c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c8458f6ae90a96f331c65edc020492e43603d488925e0631a19078708b62d2e"

  strings:
    $s1 = " = new Date();vEq4[\"setUTCFullYear\"](\"2003\");if (vEq4.getUTCFullYear().toString(10) == \"2003\") {var vRNi0 = vUPy9.split(\"" ascii
    $s2 = "var vRXw0 = new Function(\"vUPy9\", '{return vUPy9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJv0 = new Function(\"vUP" ascii
    $s3 = " return vRNi0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vRXw0 = new Function(\"vUPy9\", '{return vUPy9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJv0 = new Function(\"vUP" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}