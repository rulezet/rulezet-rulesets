rule sig_20161206_eced7d7ab8ebb6ece23886849e945eee {
  meta:
    description = "datamaliciousorder - file 20161206_eced7d7ab8ebb6ece23886849e945eee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b91fa1a5d35a394496f19204a9b032d6bb22ba26867f85e422e16dc15e98e56d"

  strings:
    $s1 = "var vTt6 = new Function(\"s\", '{var vHWg7 = new Date();vHWg7[\"setUTCFullYear\"](\"2003\");if (vHWg7.getUTCFullYear().toString(" ascii
    $s2 = "var vTt6 = new Function(\"s\", '{var vHWg7 = new Date();vHWg7[\"setUTCFullYear\"](\"2003\");if (vHWg7.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vXo7 = s.split(\"##\"); return vXo7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vEy9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}