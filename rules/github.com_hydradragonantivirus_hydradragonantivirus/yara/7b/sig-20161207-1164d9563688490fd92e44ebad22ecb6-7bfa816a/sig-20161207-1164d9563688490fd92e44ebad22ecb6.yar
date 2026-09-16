rule sig_20161207_1164d9563688490fd92e44ebad22ecb6 {
  meta:
    description = "datamaliciousorder - file 20161207_1164d9563688490fd92e44ebad22ecb6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "267e17ed2ed486138669b6ca29df4a44ee5b4db7bce60cda3bf11798a3a7ef05"

  strings:
    $s1 = "var vTZw6 = new Function(\"vDj4\", '{return vDj4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRv6 = new Function(\"vDj4" ascii
    $s2 = " new Date();vMPg4[\"setUTCFullYear\"](\"2003\");if (vMPg4.getUTCFullYear().toString(10) == \"2003\") {var vFJb9 = vDj4.split(\"#" ascii
    $s3 = "return vFJb9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vTZw6 = new Function(\"vDj4\", '{return vDj4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRv6 = new Function(\"vDj4" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}