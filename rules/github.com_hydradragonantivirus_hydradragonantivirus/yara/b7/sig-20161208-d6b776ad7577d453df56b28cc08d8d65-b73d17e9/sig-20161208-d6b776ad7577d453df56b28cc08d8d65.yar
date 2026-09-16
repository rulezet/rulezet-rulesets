rule sig_20161208_d6b776ad7577d453df56b28cc08d8d65 {
  meta:
    description = "datamaliciousorder - file 20161208_d6b776ad7577d453df56b28cc08d8d65.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbe0f41ad29670d33b5403e6cce39820e459e7ce507942f2cc601886b2996f84"

  strings:
    $s1 = "new Date();vWz9[\"setUTC\"+\"FullYear\"](\"2003\");if (vWz9.getUTCFullYear().toString(10) == \"2003\") {var vEEu3 = vYz8.split(" ascii
    $s2 = "var vMFm0 = new Function(\"vYz8\", '{return vYz8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMv4 = new Function(\"vYz8" ascii
    $s3 = "return vEEu3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vMFm0 = new Function(\"vYz8\", '{return vYz8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMv4 = new Function(\"vYz8" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}