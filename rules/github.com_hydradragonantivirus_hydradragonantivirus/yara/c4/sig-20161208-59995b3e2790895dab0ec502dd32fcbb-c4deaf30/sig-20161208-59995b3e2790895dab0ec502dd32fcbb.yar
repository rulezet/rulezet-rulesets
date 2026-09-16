rule sig_20161208_59995b3e2790895dab0ec502dd32fcbb {
  meta:
    description = "datamaliciousorder - file 20161208_59995b3e2790895dab0ec502dd32fcbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3c807a3bc657a2573f231ffeb4ac3d84fb5fa03bf8dfa44ea5b3b4add9325ec"

  strings:
    $s1 = "5 = new Date();vDa5[\"setUTC\"+\"FullYear\"](\"2003\");if (vDa5.getUTCFullYear().toString(10) == \"2003\") {var vQv6 = vSCl4.spl" ascii
    $s2 = "var vRQs7 = new Function(\"vSCl4\", '{return vSCl4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMOm2 = new Function(\"vS" ascii
    $s3 = "var vRQs7 = new Function(\"vSCl4\", '{return vSCl4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMOm2 = new Function(\"vS" ascii
    $s4 = "\"); return vQv6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}