rule sig_20161206_94448e89204bead6ec3fe87065211115 {
  meta:
    description = "datamaliciousorder - file 20161206_94448e89204bead6ec3fe87065211115.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62c7d2cce7335d8484d2770078f5938ae963b546a7976afbb556f5ed2a5328da"

  strings:
    $s1 = "var vVXw6 = new Function(\"s\", '{var vXTb5 = new Date();vXTb5[\"setUTCFullYear\"](\"2003\");if (vXTb5.getUTCFullYear().toString" ascii
    $s2 = "var vVXw6 = new Function(\"s\", '{var vXTb5 = new Date();vXTb5[\"setUTCFullYear\"](\"2003\");if (vXTb5.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vVXr8 = s.split(\"##\"); return vVXr8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vDy8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}