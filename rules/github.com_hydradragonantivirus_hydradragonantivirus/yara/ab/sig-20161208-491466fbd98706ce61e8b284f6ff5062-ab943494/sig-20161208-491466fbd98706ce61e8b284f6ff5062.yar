rule sig_20161208_491466fbd98706ce61e8b284f6ff5062 {
  meta:
    description = "datamaliciousorder - file 20161208_491466fbd98706ce61e8b284f6ff5062.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "936d28266dcd67d1fc6edd675092d7b9e472ac14a947a83fbb07deddb1902c2b"

  strings:
    $s1 = "= new Date();vBp9[\"setUTC\"+\"FullYear\"](\"2003\");if (vBp9.getUTCFullYear().toString(10) == \"2003\") {var vMRm6 = vKIr0.spli" ascii
    $s2 = "var vYr4 = new Function(\"vKIr0\", '{return vKIr0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUj7 = new Function(\"vKIr" ascii
    $s3 = "); return vMRm6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vYr4 = new Function(\"vKIr0\", '{return vKIr0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUj7 = new Function(\"vKIr" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}