rule sig_20161206_3d12e5b60f724d04cc86ae6ebde1aba0 {
  meta:
    description = "datamaliciousorder - file 20161206_3d12e5b60f724d04cc86ae6ebde1aba0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "992d445c10fab198a9ccd7844d0e7f7c747c6bc4ef9370776aae7434ab4e4929"

  strings:
    $s1 = "var vRa2 = new Function(\"s\", '{var vJn6 = new Date();vJn6[\"setUTCFullYear\"](\"2003\");if (vJn6.getUTCFullYear().toString(10)" ascii
    $s2 = "var vRa2 = new Function(\"s\", '{var vJn6 = new Date();vJn6[\"setUTCFullYear\"](\"2003\");if (vJn6.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vRRx4 = s.split(\"##\"); return vRRx4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vVp1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}