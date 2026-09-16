rule sig_20161208_239cb014cdc030132ec5d44060fff715 {
  meta:
    description = "datamaliciousorder - file 20161208_239cb014cdc030132ec5d44060fff715.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f7fe8d76aa38b4005a477f3cde0612e21a995234fa603e2e998b003be45c325"

  strings:
    $s1 = "var vAq9 = new Function(\"vAe0\", '{return vAe0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJUg7 = new Function(\"vAe0" ascii
    $s2 = " new Date();vONk7[\"setUTC\"+\"FullYear\"](\"2003\");if (vONk7.getUTCFullYear().toString(10) == \"2003\") {var vFFx3 = vAe0.spli" ascii
    $s3 = "); return vFFx3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vAq9 = new Function(\"vAe0\", '{return vAe0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJUg7 = new Function(\"vAe0" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}