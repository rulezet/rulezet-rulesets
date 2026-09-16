rule sig_20161206_56529a5e69451881eccd4ff31e69db0b {
  meta:
    description = "datamaliciousorder - file 20161206_56529a5e69451881eccd4ff31e69db0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04b9d67ebed02fcc1b0134ec341a4615ef4f310acc0e61bdce6a6b5f0e96a80a"

  strings:
    $s1 = "var vLFi9 = new Function(\"s\", '{var vUh3 = new Date();vUh3[\"setUTCFullYear\"](\"2003\");if (vUh3.getUTCFullYear().toString(10" ascii
    $s2 = "var vLFi9 = new Function(\"s\", '{var vUh3 = new Date();vUh3[\"setUTCFullYear\"](\"2003\");if (vUh3.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vSZi4 = s.split(\"##\"); return vSZi4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vQg2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}