rule sig_20161208_cc892098906fc19a3e901b82afdf673a {
  meta:
    description = "datamaliciousorder - file 20161208_cc892098906fc19a3e901b82afdf673a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f41424464329e82918d6b130b15b4bb6ac1e50d13d57158ecdcef5a22142261"

  strings:
    $s1 = "var vEv0 = new Function(\"vRf8\", '{return vRf8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHq4 = new Function(\"vRf8\"" ascii
    $s2 = "new Date();vYTi0[\"setUTC\"+\"FullYear\"](\"2003\");if (vYTi0.getUTCFullYear().toString(10) == \"2003\") {var vUTv7 = vRf8.split" ascii
    $s3 = "; return vUTv7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEv0 = new Function(\"vRf8\", '{return vRf8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHq4 = new Function(\"vRf8\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}