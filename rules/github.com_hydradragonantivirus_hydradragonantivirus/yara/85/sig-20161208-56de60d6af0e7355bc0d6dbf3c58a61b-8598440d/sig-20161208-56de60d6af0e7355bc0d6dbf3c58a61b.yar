rule sig_20161208_56de60d6af0e7355bc0d6dbf3c58a61b {
  meta:
    description = "datamaliciousorder - file 20161208_56de60d6af0e7355bc0d6dbf3c58a61b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac4f53c63a3f536b515c368ab5ab6b4be8747e8f811d8821c6f6f171498309f5"

  strings:
    $s1 = " = new Date();vTt9[\"setUTC\"+\"FullYear\"](\"2003\");if (vTt9.getUTCFullYear().toString(10) == \"2003\") {var vOt2 = vUUv7.spli" ascii
    $s2 = "var vXQd4 = new Function(\"vUUv7\", '{return vUUv7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRz1 = new Function(\"vUU" ascii
    $s3 = "var vXQd4 = new Function(\"vUUv7\", '{return vUUv7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRz1 = new Function(\"vUU" ascii
    $s4 = "); return vOt2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}