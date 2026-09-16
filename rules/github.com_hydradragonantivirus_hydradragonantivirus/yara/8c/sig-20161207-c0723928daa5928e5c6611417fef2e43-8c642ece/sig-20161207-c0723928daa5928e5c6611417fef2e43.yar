rule sig_20161207_c0723928daa5928e5c6611417fef2e43 {
  meta:
    description = "datamaliciousorder - file 20161207_c0723928daa5928e5c6611417fef2e43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b0a524b4603e2abd8c9038b2dc338fd7c6cd9d836b239b23283ecda1aca5de4"

  strings:
    $s1 = "var vSh1 = new Function(\"vRb8\", '{return vRb8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWd0 = new Function(\"vRb8\"" ascii
    $s2 = "new Date();vHIn5[\"setUTCFullYear\"](\"2003\");if (vHIn5.getUTCFullYear().toString(10) == \"2003\") {var vUs8 = vRb8.split(\"###" ascii
    $s3 = "var vSh1 = new Function(\"vRb8\", '{return vRb8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWd0 = new Function(\"vRb8\"" ascii
    $s4 = "turn vUs8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}