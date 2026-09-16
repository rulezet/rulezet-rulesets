rule sig_20161208_7ecd361fba96bdec1bdf0fc25cddecd7 {
  meta:
    description = "datamaliciousorder - file 20161208_7ecd361fba96bdec1bdf0fc25cddecd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52a1fc8c8839d64826a0bd557a0b7be8a87d5d79e04b6d8f5b78a8c73bfcc5de"

  strings:
    $s1 = "var vEe1 = new Function(\"vNUc6\", '{return vNUc6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXZv7 = new Function(\"vNU" ascii
    $s2 = " = new Date();vBl6[\"setUTC\"+\"FullYear\"](\"2003\");if (vBl6.getUTCFullYear().toString(10) == \"2003\") {var vHNi4 = vNUc6.spl" ascii
    $s3 = "\"); return vHNi4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEe1 = new Function(\"vNUc6\", '{return vNUc6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXZv7 = new Function(\"vNU" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}