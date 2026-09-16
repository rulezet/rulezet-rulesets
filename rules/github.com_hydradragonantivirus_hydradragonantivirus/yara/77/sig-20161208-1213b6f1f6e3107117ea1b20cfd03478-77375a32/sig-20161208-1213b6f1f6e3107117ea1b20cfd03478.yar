rule sig_20161208_1213b6f1f6e3107117ea1b20cfd03478 {
  meta:
    description = "datamaliciousorder - file 20161208_1213b6f1f6e3107117ea1b20cfd03478.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "834b23d05e4cfa796b04aa74af800e14b7b6276ddfa6be07491e8e508f496caf"

  strings:
    $s1 = "var vJJz7 = new Function(\"vRx5\", '{return vRx5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGr7 = new Function(\"vRx5" ascii
    $s2 = " new Date();vZCo8[\"setUTC\"+\"FullYear\"](\"2003\");if (vZCo8.getUTCFullYear().toString(10) == \"2003\") {var vVXs4 = vRx5.spli" ascii
    $s3 = "); return vVXs4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vJJz7 = new Function(\"vRx5\", '{return vRx5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGr7 = new Function(\"vRx5" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}