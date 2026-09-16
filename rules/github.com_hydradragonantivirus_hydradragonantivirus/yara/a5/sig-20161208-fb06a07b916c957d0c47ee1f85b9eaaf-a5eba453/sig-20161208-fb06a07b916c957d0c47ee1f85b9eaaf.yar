rule sig_20161208_fb06a07b916c957d0c47ee1f85b9eaaf {
  meta:
    description = "datamaliciousorder - file 20161208_fb06a07b916c957d0c47ee1f85b9eaaf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf738ccdd8d812e27e98a93a9a3bfa9b40d176a70766a96b497ec74eac186060"

  strings:
    $s1 = "var vMe2 = new Function(\"vGz0\", '{return vGz0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOd2 = new Function(\"vGz0\"" ascii
    $s2 = "ew Date();vVb1[\"setUTC\"+\"FullYear\"](\"2003\");if (vVb1.getUTCFullYear().toString(10) == \"2003\") {var vBl5 = vGz0.split(\"#" ascii
    $s3 = "turn vBl5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vMe2 = new Function(\"vGz0\", '{return vGz0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOd2 = new Function(\"vGz0\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}