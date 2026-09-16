rule sig_20161207_5fb9f8c7f6a1a8b6dbd5d5091237a76d {
  meta:
    description = "datamaliciousorder - file 20161207_5fb9f8c7f6a1a8b6dbd5d5091237a76d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5fb11b18376815929d5193d499da206b5076d0be3d28d5f420b0bdff3be7b9c"

  strings:
    $s1 = "new Date();vCc2[\"setUTCFullYear\"](\"2003\");if (vCc2.getUTCFullYear().toString(10) == \"2003\") {var vCUo3 = vTw1.split(\"####" ascii
    $s2 = "var vNz8 = new Function(\"vTw1\", '{return vTw1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHFr0 = new Function(\"vTw1" ascii
    $s3 = "urn vCUo3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNz8 = new Function(\"vTw1\", '{return vTw1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHFr0 = new Function(\"vTw1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}