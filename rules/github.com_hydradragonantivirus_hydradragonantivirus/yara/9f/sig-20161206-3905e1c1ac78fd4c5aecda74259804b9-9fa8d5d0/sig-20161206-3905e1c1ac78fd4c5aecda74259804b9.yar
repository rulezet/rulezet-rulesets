rule sig_20161206_3905e1c1ac78fd4c5aecda74259804b9 {
  meta:
    description = "datamaliciousorder - file 20161206_3905e1c1ac78fd4c5aecda74259804b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed0dc01f62a690ff2aa05bc84fb75258802aab965990dfee2f9c6f8a07a0d58b"

  strings:
    $s1 = "var vFn5 = new Function(\"s\", '{var vVs8 = new Date();vVs8[\"setUTCFullYear\"](\"2003\");if (vVs8.getUTCFullYear().toString(10)" ascii
    $s2 = "var vFn5 = new Function(\"s\", '{var vVs8 = new Date();vVs8[\"setUTCFullYear\"](\"2003\");if (vVs8.getUTCFullYear().toString(10)" ascii
    $s3 = "function vMMa1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vPh1 = s.split(\"##\"); return vPh1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}