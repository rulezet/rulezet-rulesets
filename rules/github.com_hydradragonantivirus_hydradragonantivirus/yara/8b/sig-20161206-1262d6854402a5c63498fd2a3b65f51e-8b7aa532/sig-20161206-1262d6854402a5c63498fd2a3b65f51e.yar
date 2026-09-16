rule sig_20161206_1262d6854402a5c63498fd2a3b65f51e {
  meta:
    description = "datamaliciousorder - file 20161206_1262d6854402a5c63498fd2a3b65f51e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6357c3158ad2f38c43772d60a06ab115279d03fbea90a273993dfdb232aac78"

  strings:
    $s1 = "var vFe5 = new Function(\"s\", '{var vUw9 = new Date();vUw9[\"setUTCFullYear\"](\"2003\");if (vUw9.getUTCFullYear().toString(10)" ascii
    $s2 = "var vFe5 = new Function(\"s\", '{var vUw9 = new Date();vUw9[\"setUTCFullYear\"](\"2003\");if (vUw9.getUTCFullYear().toString(10)" ascii
    $s3 = "function vZPn6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vLr6 = s.split(\"##\"); return vLr6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}