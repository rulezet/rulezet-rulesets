rule sig_20160822_3199c17dae382f6c0de7dcc92436aee5 {
  meta:
    description = "datamaliciousorder - file 20160822_3199c17dae382f6c0de7dcc92436aee5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6e62704c2644c39174ed68f52ec4803ad8409caec3ce6e6be649c07097db348"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}