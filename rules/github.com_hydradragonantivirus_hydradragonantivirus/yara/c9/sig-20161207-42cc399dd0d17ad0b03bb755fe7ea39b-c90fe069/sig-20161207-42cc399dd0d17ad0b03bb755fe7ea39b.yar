rule sig_20161207_42cc399dd0d17ad0b03bb755fe7ea39b {
  meta:
    description = "datamaliciousorder - file 20161207_42cc399dd0d17ad0b03bb755fe7ea39b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39f707c69a4a7e873f05afa2144a009eae65a0239ac890a59a3233215f884761"

  strings:
    $s1 = "var vPWk2 = new Function(\"vTw8\", '{return vTw8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPAr5 = new Function(\"vTw8" ascii
    $s2 = "= new Date();vZSc3[\"setUTCFullYear\"](\"2003\");if (vZSc3.getUTCFullYear().toString(10) == \"2003\") {var vPc3 = vTw8.split(\"#" ascii
    $s3 = "var vPWk2 = new Function(\"vTw8\", '{return vTw8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPAr5 = new Function(\"vTw8" ascii
    $s4 = "return vPc3.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}