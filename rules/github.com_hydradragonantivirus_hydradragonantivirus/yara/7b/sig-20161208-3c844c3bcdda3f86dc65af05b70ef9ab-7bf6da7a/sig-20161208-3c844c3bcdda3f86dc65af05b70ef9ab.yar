rule sig_20161208_3c844c3bcdda3f86dc65af05b70ef9ab {
  meta:
    description = "datamaliciousorder - file 20161208_3c844c3bcdda3f86dc65af05b70ef9ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4ced0a1f8cd70190c2061f2f6f1634b4582b8af3fac40309e870336449349d0"

  strings:
    $s1 = " = new Date();vUp3[\"setUTC\"+\"FullYear\"](\"2003\");if (vUp3.getUTCFullYear().toString(10) == \"2003\") {var vGAc7 = vCFw3.spl" ascii
    $s2 = "var vOCq0 = new Function(\"vCFw3\", '{return vCFw3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSb0 = new Function(\"vCF" ascii
    $s3 = "var vOCq0 = new Function(\"vCFw3\", '{return vCFw3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSb0 = new Function(\"vCF" ascii
    $s4 = "\"); return vGAc7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}