rule sig_20161207_78e14d0eec19751dfeb4d0d885cc6a23 {
  meta:
    description = "datamaliciousorder - file 20161207_78e14d0eec19751dfeb4d0d885cc6a23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3267ff47c47d50a068f27aa9277deaadcb21b59751f616343079aad52fc23ef5"

  strings:
    $s1 = "var vDf8 = new Function(\"vUHo6\", '{return vUHo6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIYa7 = new Function(\"vUH" ascii
    $s2 = "7 = new Date();vMHb7[\"setUTCFullYear\"](\"2003\");if (vMHb7.getUTCFullYear().toString(10) == \"2003\") {var vHa9 = vUHo6.split(" ascii
    $s3 = "var vDf8 = new Function(\"vUHo6\", '{return vUHo6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIYa7 = new Function(\"vUH" ascii
    $s4 = "); return vHa9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}