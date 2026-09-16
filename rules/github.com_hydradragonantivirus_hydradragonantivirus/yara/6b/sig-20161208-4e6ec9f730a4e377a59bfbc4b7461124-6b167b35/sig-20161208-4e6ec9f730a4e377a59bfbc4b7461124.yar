rule sig_20161208_4e6ec9f730a4e377a59bfbc4b7461124 {
  meta:
    description = "datamaliciousorder - file 20161208_4e6ec9f730a4e377a59bfbc4b7461124.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b49dc7802f2e2174e9f5803f04c7508254ab0a916245da094664f169f06f423"

  strings:
    $s1 = " = new Date();vXLg5[\"setUTC\"+\"FullYear\"](\"2003\");if (vXLg5.getUTCFullYear().toString(10) == \"2003\") {var vMDe9 = vIPo3.s" ascii
    $s2 = "var vAd3 = new Function(\"vIPo3\", '{return vIPo3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBw3 = new Function(\"vIPo" ascii
    $s3 = "var vAd3 = new Function(\"vIPo3\", '{return vIPo3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vBw3 = new Function(\"vIPo" ascii
    $s4 = "##\"); return vMDe9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}