rule sig_20161208_09b3ca1afbc484ffafb02ac312e8c024 {
  meta:
    description = "datamaliciousorder - file 20161208_09b3ca1afbc484ffafb02ac312e8c024.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e929b8c598a93676124152283b93350a76d75c69ac3cca62b94c40cfd726627"

  strings:
    $s1 = "o8 = new Date();vMBo8[\"setUTC\"+\"FullYear\"](\"2003\");if (vMBo8.getUTCFullYear().toString(10) == \"2003\") {var vBSr3 = vTYs6" ascii
    $s2 = "var vZFt9 = new Function(\"vTYs6\", '{return vTYs6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYVh9 = new Function(\"vT" ascii
    $s3 = "var vZFt9 = new Function(\"vTYs6\", '{return vTYs6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYVh9 = new Function(\"vT" ascii
    $s4 = "####\"); return vBSr3.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}