rule sig_20161206_0818561a89e166e4ffba98fa09c10845 {
  meta:
    description = "datamaliciousorder - file 20161206_0818561a89e166e4ffba98fa09c10845.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "510d0d7c0ac68959a126854bb988c6c9c820a282ba994151e91b3097acb528db"

  strings:
    $s1 = "var vHc1 = new Function(\"s\", '{var vBs0 = new Date();vBs0[\"setUTCFullYear\"](\"2003\");if (vBs0.getUTCFullYear().toString(10)" ascii
    $s2 = "var vHc1 = new Function(\"s\", '{var vBs0 = new Date();vBs0[\"setUTCFullYear\"](\"2003\");if (vBs0.getUTCFullYear().toString(10)" ascii
    $s3 = "function vAn4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vTBg6 = s.split(\"##\"); return vTBg6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}