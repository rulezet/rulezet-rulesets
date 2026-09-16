rule sig_20161208_1dbe7d37f5d9e0ea9ea30e4f7e5d9c1c {
  meta:
    description = "datamaliciousorder - file 20161208_1dbe7d37f5d9e0ea9ea30e4f7e5d9c1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7495b4540947ed19f81925685c00126e8c7248d194c018d5c86e1315e6244de"

  strings:
    $s1 = "= new Date();vYo5[\"setUTC\"+\"FullYear\"](\"2003\");if (vYo5.getUTCFullYear().toString(10) == \"2003\") {var vKGe7 = vWFx8.spli" ascii
    $s2 = "var vUq4 = new Function(\"vWFx8\", '{return vWFx8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSe5 = new Function(\"vWFx" ascii
    $s3 = "); return vKGe7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vUq4 = new Function(\"vWFx8\", '{return vWFx8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSe5 = new Function(\"vWFx" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}